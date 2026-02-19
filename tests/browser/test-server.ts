import { spawn } from "node:child_process"

export interface TestServer{
    stop(): Promise<number>;
}

export const useTestServer = (cwd: string) => {
  // Implement your test server logic here

  const start = async (): Promise<TestServer> => {
     
    const abortCont = new AbortController();

    // Runs the development server
    const serverProc = spawn('task', ['dev-server-run'], {
        cwd,
        signal: abortCont.signal,
        killSignal: 'SIGINT', // webserver accepts interrupt when aborted
        stdio: ['ignore', 'inherit', 'inherit'], 
        detached: false
    });

    // Wait for process to spawn - give it a moment to start up
    await new Promise(resolve => setTimeout(resolve, 2000));

    const exitPromise = new Promise<number>((resolve, reject) => {
        serverProc.on('exit', (code) => resolve(code ?? 0));
        serverProc.on('error', reject);
    });

    // Check if the server process exited with an error
    if (serverProc.exitCode !== null){
        throw new Error(`Test server exited immediately with code ${serverProc.exitCode}`);
    }

     return {
        stop: () => {
            // Stop the development server by sending SIGINT and 
            // waiting for the exit code
            abortCont.abort();
            return exitPromise;
        }
    };
  }
 
  return { start }
}
