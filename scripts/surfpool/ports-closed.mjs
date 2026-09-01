import net from "node:net";

const [host, ...rawPorts] = process.argv.slice(2);
if (!host || rawPorts.length === 0) {
  throw new Error("usage: ports-closed.mjs <host> <port> [port ...]");
}

async function isOpen(port) {
  return await new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port: Number(port) });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`timed out probing ${host}:${port}`));
    }, 500);
    socket.once("connect", () => {
      clearTimeout(timer);
      socket.destroy();
      resolve(true);
    });
    socket.once("error", (error) => {
      clearTimeout(timer);
      if (["ECONNREFUSED", "EHOSTUNREACH"].includes(error.code)) {
        resolve(false);
      } else {
        reject(error);
      }
    });
  });
}

const openPorts = [];
for (const port of rawPorts) {
  if (await isOpen(port)) openPorts.push(port);
}
if (openPorts.length > 0) {
  throw new Error(`ports remain open on ${host}: ${openPorts.join(", ")}`);
}
console.log(`ports closed on ${host}: ${rawPorts.join(", ")}`);
