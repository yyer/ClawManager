import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 9002,
    host: true,
    proxy: {
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
