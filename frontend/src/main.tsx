import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
// 2026-09-05: secplane-theme.css and protection-tokens.css moved
// to the standalone secplane SPA (secplane-server/frontend/src/styles/).
// They are no longer loaded into the clawmanager SPA.
import './index.css'
import App from './App.tsx'

const rootElement = document.getElementById('root')
if (!rootElement) {
  throw new Error('Failed to find the root element')
}

createRoot(rootElement).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
