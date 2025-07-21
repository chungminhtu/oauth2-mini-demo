import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'

export default defineConfig({
  root: './oauth2/app1',
  server: {
    port: 3000
  },
  test: {
    globals: true,
    environment: 'node',
  },
  plugins: [react()],
  base: './',
})
