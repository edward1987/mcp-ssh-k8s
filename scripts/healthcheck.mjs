import { request } from 'node:http';
const req = request({ hostname: '127.0.0.1', port: Number(process.env.GATEWAY_PORT ?? 8080), path: '/readyz', timeout: 3000 }, res => {
  res.resume();
  res.on('end', () => process.exit(res.statusCode === 200 ? 0 : 1));
});
req.on('timeout', () => req.destroy());
req.on('error', () => process.exit(1));
req.end();
