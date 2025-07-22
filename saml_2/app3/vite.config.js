import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'

export default defineConfig({
    root: './saml_2/app3',
    plugins: [react()],
    root: './saml_2/app3',
    server: {
        port: 4003,
        open: true
    },
})