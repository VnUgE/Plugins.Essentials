import { useAxios, useSession } from '@vnuge/vnlib.browser';
import { afterAll, beforeAll } from 'vitest';
import { type TestServer, useTestServer } from './test-server';
import { vnlib } from './fixtures';

let server: TestServer;

//Makes an initial request to the server to obtain a session cookie
beforeAll(async () => {

  // const { start } = useTestServer(process.cwd());
  // server = await start();

  const { get } = useAxios(vnlib)
  await get('/')

})

//Always reset the login state after all testing as completed
afterAll(() => {
  const { clearClientSecInfo } = useSession(vnlib)
  clearClientSecInfo()
})

// afterAll(async () => {
//   // Stop the test server
//   const code = await server?.stop();
//   console.log(`Test server stopped with exit code ${code}`);
// })