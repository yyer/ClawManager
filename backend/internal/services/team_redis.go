package services

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type redisStreamMessage struct {
	ID     string
	Fields map[string]string
}

type redisBus struct {
	address  string
	username string
	password string
	db       int
	useTLS   bool
}

func newRedisBus(rawURL string) (*redisBus, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("redis url is invalid: %w", err)
	}
	if parsed.Scheme != "redis" && parsed.Scheme != "rediss" {
		return nil, fmt.Errorf("redis url scheme must be redis or rediss")
	}
	address := parsed.Host
	if !strings.Contains(address, ":") {
		address += ":6379"
	}
	username := parsed.User.Username()
	password, _ := parsed.User.Password()
	dbIndex := 0
	if path := strings.Trim(parsed.Path, "/"); path != "" {
		parsedDB, err := strconv.Atoi(path)
		if err != nil {
			return nil, fmt.Errorf("redis db index is invalid: %w", err)
		}
		dbIndex = parsedDB
	}
	return &redisBus{
		address:  address,
		username: username,
		password: password,
		db:       dbIndex,
		useTLS:   parsed.Scheme == "rediss",
	}, nil
}

func (b *redisBus) XAdd(ctx context.Context, key string, fields map[string]string) (string, error) {
	args := []string{"XADD", key, "*"}
	for field, value := range fields {
		args = append(args, field, value)
	}
	reply, err := b.do(ctx, args...)
	if err != nil {
		return "", err
	}
	id, ok := reply.(string)
	if !ok || strings.TrimSpace(id) == "" {
		return "", fmt.Errorf("unexpected redis XADD response")
	}
	return id, nil
}

func (b *redisBus) SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		ttl = time.Second
	}
	reply, err := b.do(ctx, "SET", key, value, "NX", "PX", fmt.Sprintf("%d", ttl.Milliseconds()))
	if err != nil {
		return false, err
	}
	if reply == nil {
		return false, nil
	}
	return reply == "OK", nil
}

func (b *redisBus) Del(ctx context.Context, key string) error {
	_, err := b.do(ctx, "DEL", key)
	return err
}

// ACLSetUser creates or updates a Redis ACL user with the given rules.
// Wraps `ACL SETUSER <name> <rule...>`. Returns error if Redis rejects
// (e.g. unsupported on Redis < 6.0, or malformed rules).
func (b *redisBus) ACLSetUser(ctx context.Context, name string, rules ...string) error {
	args := append([]string{"ACL", "SETUSER", name}, rules...)
	_, err := b.do(ctx, args...)
	return err
}

// ACLDelUser removes a Redis ACL user. Wraps `ACL DELUSER <name>`.
// No-op (returns nil) if the user does not exist.
func (b *redisBus) ACLDelUser(ctx context.Context, name string) error {
	_, err := b.do(ctx, "ACL", "DELUSER", name)
	return err
}

// ACLListUsers returns the list of ACL user names. Wraps `ACL USERS`.
func (b *redisBus) ACLListUsers(ctx context.Context) ([]string, error) {
	reply, err := b.do(ctx, "ACL", "USERS")
	if err != nil {
		return nil, err
	}
	root, ok := reply.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected ACL USERS response")
	}
	users := make([]string, 0, len(root))
	for _, item := range root {
		if s, ok := item.(string); ok {
			users = append(users, s)
		}
	}
	return users, nil
}

// ACLSave persists ACL rules to the aclfile if one is configured. Wraps
// `ACL SAVE`. Returns error if no aclfile is configured (caller ignores).
func (b *redisBus) ACLSave(ctx context.Context) error {
	_, err := b.do(ctx, "ACL", "SAVE")
	return err
}

func (b *redisBus) XRead(ctx context.Context, key, lastID string, block time.Duration) ([]redisStreamMessage, error) {
	blockMillis := int(block / time.Millisecond)
	if blockMillis <= 0 {
		blockMillis = 5000
	}
	reply, err := b.do(ctx, "XREAD", "BLOCK", strconv.Itoa(blockMillis), "STREAMS", key, lastID)
	if err != nil {
		return nil, err
	}
	if reply == nil {
		return nil, nil
	}
	root, ok := reply.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected redis XREAD response")
	}
	var messages []redisStreamMessage
	for _, streamRaw := range root {
		stream, ok := streamRaw.([]interface{})
		if !ok || len(stream) != 2 {
			continue
		}
		messageList, ok := stream[1].([]interface{})
		if !ok {
			continue
		}
		for _, messageRaw := range messageList {
			message, ok := messageRaw.([]interface{})
			if !ok || len(message) != 2 {
				continue
			}
			id, ok := message[0].(string)
			if !ok {
				continue
			}
			fieldList, ok := message[1].([]interface{})
			if !ok {
				continue
			}
			fields := map[string]string{}
			for i := 0; i+1 < len(fieldList); i += 2 {
				field, okField := fieldList[i].(string)
				value, okValue := fieldList[i+1].(string)
				if okField && okValue {
					fields[field] = value
				}
			}
			messages = append(messages, redisStreamMessage{ID: id, Fields: fields})
		}
	}
	return messages, nil
}

func (b *redisBus) XRevRange(ctx context.Context, key string, count int) ([]redisStreamMessage, error) {
	if count <= 0 {
		count = 100
	}
	reply, err := b.do(ctx, "XREVRANGE", key, "+", "-", "COUNT", strconv.Itoa(count))
	if err != nil {
		return nil, err
	}
	root, ok := reply.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected redis XREVRANGE response")
	}
	return parseRedisStreamEntries(root), nil
}

// XLen returns the number of entries in a stream. Wraps `XLEN key`.
func (b *redisBus) XLen(ctx context.Context, key string) (int, error) {
	reply, err := b.do(ctx, "XLEN", key)
	if err != nil {
		return 0, err
	}
	count, ok := reply.(int64)
	if !ok {
		return 0, fmt.Errorf("unexpected redis XLEN response")
	}
	return int(count), nil
}

// XTrim caps a stream to approximately maxLen entries. Wraps
// `XTRIM key MAXLEN ~N`. The `~` flag allows Redis to trim slightly below
// N for performance; callers should treat the resulting length as advisory.
func (b *redisBus) XTrim(ctx context.Context, key string, maxLen int) (int, error) {
	reply, err := b.do(ctx, "XTRIM", key, "MAXLEN", "~", strconv.Itoa(maxLen))
	if err != nil {
		return 0, err
	}
	trimmed, ok := reply.(int64)
	if !ok {
		return 0, fmt.Errorf("unexpected redis XTRIM response")
	}
	return int(trimmed), nil
}

// XDel removes the given IDs from a stream. Wraps `XDEL key id...`.
func (b *redisBus) XDel(ctx context.Context, key string, ids ...string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	args := append([]string{"XDEL", key}, ids...)
	reply, err := b.do(ctx, args...)
	if err != nil {
		return 0, err
	}
	deleted, ok := reply.(int64)
	if !ok {
		return 0, fmt.Errorf("unexpected redis XDEL response")
	}
	return int(deleted), nil
}

// HKeys returns the field names of a Redis hash. Wraps `HKEYS key`.
func (b *redisBus) HKeys(ctx context.Context, key string) ([]string, error) {
	reply, err := b.do(ctx, "HKEYS", key)
	if err != nil {
		return nil, err
	}
	root, ok := reply.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected redis HKEYS response")
	}
	fields := make([]string, 0, len(root))
	for _, item := range root {
		if s, ok := item.(string); ok {
			fields = append(fields, s)
		}
	}
	return fields, nil
}

func parseRedisStreamEntries(entries []interface{}) []redisStreamMessage {
	messages := make([]redisStreamMessage, 0, len(entries))
	for _, messageRaw := range entries {
		message, ok := messageRaw.([]interface{})
		if !ok || len(message) != 2 {
			continue
		}
		id, ok := message[0].(string)
		if !ok {
			continue
		}
		fieldList, ok := message[1].([]interface{})
		if !ok {
			continue
		}
		fields := map[string]string{}
		for i := 0; i+1 < len(fieldList); i += 2 {
			field, okField := fieldList[i].(string)
			value, okValue := fieldList[i+1].(string)
			if okField && okValue {
				fields[field] = value
			}
		}
		messages = append(messages, redisStreamMessage{ID: id, Fields: fields})
	}
	return messages
}

func (b *redisBus) do(ctx context.Context, args ...string) (interface{}, error) {
	conn, reader, err := b.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := writeRedisCommand(conn, args...); err != nil {
		return nil, err
	}
	return readRedisReply(reader)
}

func (b *redisBus) connect(ctx context.Context) (net.Conn, *bufio.Reader, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	var conn net.Conn
	var err error
	if b.useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", b.address, &tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", b.address)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect redis: %w", err)
	}
	reader := bufio.NewReader(conn)
	if b.username != "" && b.password != "" {
		if err := writeRedisCommand(conn, "AUTH", b.username, b.password); err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
		if _, err := readRedisReply(reader); err != nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("redis auth failed: %w", err)
		}
	} else if b.password != "" {
		if err := writeRedisCommand(conn, "AUTH", b.password); err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
		if _, err := readRedisReply(reader); err != nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("redis auth failed: %w", err)
		}
	}
	if b.db > 0 {
		if err := writeRedisCommand(conn, "SELECT", strconv.Itoa(b.db)); err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
		if _, err := readRedisReply(reader); err != nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("redis select db failed: %w", err)
		}
	}
	return conn, reader, nil
}

func writeRedisCommand(conn net.Conn, args ...string) error {
	var builder strings.Builder
	builder.WriteString("*")
	builder.WriteString(strconv.Itoa(len(args)))
	builder.WriteString("\r\n")
	for _, arg := range args {
		builder.WriteString("$")
		builder.WriteString(strconv.Itoa(len(arg)))
		builder.WriteString("\r\n")
		builder.WriteString(arg)
		builder.WriteString("\r\n")
	}
	if _, err := conn.Write([]byte(builder.String())); err != nil {
		return fmt.Errorf("failed to write redis command: %w", err)
	}
	return nil
}

func readRedisReply(reader *bufio.Reader) (interface{}, error) {
	prefix, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	switch prefix {
	case '+':
		line, err := readRedisLine(reader)
		return line, err
	case '-':
		line, _ := readRedisLine(reader)
		return nil, fmt.Errorf("redis error: %s", line)
	case ':':
		line, err := readRedisLine(reader)
		if err != nil {
			return nil, err
		}
		return strconv.ParseInt(line, 10, 64)
	case '$':
		line, err := readRedisLine(reader)
		if err != nil {
			return nil, err
		}
		size, err := strconv.Atoi(line)
		if err != nil {
			return nil, err
		}
		if size < 0 {
			return nil, nil
		}
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, err
		}
		return string(buf[:size]), nil
	case '*':
		line, err := readRedisLine(reader)
		if err != nil {
			return nil, err
		}
		count, err := strconv.Atoi(line)
		if err != nil {
			return nil, err
		}
		if count < 0 {
			return nil, nil
		}
		items := make([]interface{}, 0, count)
		for i := 0; i < count; i++ {
			item, err := readRedisReply(reader)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return items, nil
	default:
		return nil, fmt.Errorf("unexpected redis reply prefix %q", prefix)
	}
}

func readRedisLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}
