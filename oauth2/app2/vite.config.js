import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'

export default defineConfig({
    plugins: [react()],
    root: './oauth2/app2',
    base: './',
    server: {
        port: 3001,
        open: true
    },
    build: {
        outDir: '../dist-app2'
    }
})