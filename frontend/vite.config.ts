import {defineConfig} from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
export default defineConfig({plugins:[react(),tailwindcss()],build:{rollupOptions:{output:{manualChunks:{graph:['@xyflow/react'],charts:['recharts'],react:['react','react-dom']}}}},server:{proxy:{'/api':{target:process.env.API_PROXY_TARGET || 'http://127.0.0.1:8000',changeOrigin:true}}}});
