import { configureApi, useAxios, useSession } from '@vnuge/vnlib.browser';
import { afterAll, beforeAll } from 'vitest';

configureApi({
  account:{
      endpointUrl: '/api/account'
  },
  axios:{
      baseURL:"/api", //Matches vitest.config.ts proxy target to route api requests to the test server
      withCredentials: true
  },
  session:{
      loginCookieName: 'li',
  },
  storage: localStorage
})

//Makes an initial request to the server to obtain a session cookie
beforeAll(async () => {
  const { get } = useAxios()
  await get('/')
})

//Always reset the login state after all testing as completed
afterAll(() => {
  const { clearLoginState } = useSession()
  clearLoginState()
})