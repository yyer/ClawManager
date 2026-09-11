package services

import (
	"testing"

	"clawreef/internal/config"
	"clawreef/internal/models"
	"clawreef/internal/repository"
)

type registrationUserRepo struct {
	repository.UserRepository
	created *models.User
}

func (r *registrationUserRepo) GetByUsername(string) (*models.User, error) { return nil, nil }
func (r *registrationUserRepo) GetByEmail(string) (*models.User, error)    { return nil, nil }
func (r *registrationUserRepo) Create(user *models.User) error {
	user.ID = 42
	r.created = user
	return nil
}

type registrationQuotaRepo struct {
	repository.QuotaRepository
	createdFor int
}

func (r *registrationQuotaRepo) CreateDefaultQuota(userID int) (*models.UserQuota, error) {
	r.createdFor = userID
	return &models.UserQuota{UserID: userID}, nil
}

func TestRegistrationInitializesOrdinaryQuota(t *testing.T) {
	users := &registrationUserRepo{}
	quotas := &registrationQuotaRepo{}
	auth := NewAuthService(users, config.JWTConfig{}, WithQuotaRepository(quotas))
	user, err := auth.Register("desktop-user", "desktop@example.invalid", "test-password-only")
	if err != nil {
		t.Fatal(err)
	}
	if quotas.createdFor != user.ID {
		t.Fatalf("registered user has no ordinary quota: createdFor=%d userID=%d", quotas.createdFor, user.ID)
	}
	if user.Role != "user" {
		t.Fatal("registration changed ordinary role")
	}
}
