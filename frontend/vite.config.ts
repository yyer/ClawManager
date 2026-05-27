import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 9002,
    host: true,
    proxy: {
      // ksec-bridge dev proxy: when running ksec-bridge locally via
      // `npm run dev` (default 127.0.0.1:9101), front-end `/api/host/*`
      // calls land directly on it — mirrors the prod nginx rewrite rule.
      // Must come BEFORE the generic `/api` rule (vite picks first match).
      '/api/host': {
        target: 'http://127.0.0.1:9101',
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api\/host/, '/agent/v1'),
      },
      '/api': {
        // ClawManager backend now runs in minikube as Deployment
        // clawmanager-app (Service clawmanager-gateway type=NodePort in ns
        // clawreef-system). Targeting `minikube ip`:30901 directly is more
        // reliable than `kubectl port-forward` (host port 30901 is blocked
        // by some local rule, plus port-forwards die on idle / SIGKILL).
        // If the minikube IP changes, refresh with: `minikube ip`.
        target: 'http://192.168.49.2:30901',
        changeOrigin: true,
        ws: true,
      },
    },
  },
})
