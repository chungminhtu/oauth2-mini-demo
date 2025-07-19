import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'

export default defineConfig({
    plugins: [react()],
    root: './saml_2/app4',
    server: {
        port: 3003,
        open: true
    },
    build: {
        outDir: '../dist-app4'
    }
})