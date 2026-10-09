import {defineConfig} from 'vitest/config'
import react from '@vitejs/plugin-react'
export default defineConfig({plugins:[react()],server:{proxy:{'/api':'http://127.0.0.1:8021','/health':'http://127.0.0.1:8021'}},test:{environment:'jsdom',setupFiles:['./src/test-setup.ts'],restoreMocks:true}})
