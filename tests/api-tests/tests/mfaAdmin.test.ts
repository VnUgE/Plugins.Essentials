import { describe, expect, it } from 'vitest';

import { useAccount, useAccountRpc, useFidoApi, useMfaApi, useOtpApi, useTotpApi } from '@vnuge/vnlib.browser'
const { login, logout } = useAccount()
const { isEnabled, sendRequest, getData } = useMfaApi()
const { getData:getAccStatus } = useAccountRpc()
const testUser = { userName: 'test@test.com', password: 'Password12!' }

describe('Before a user modifes their profile', () => {
    it('Logs the user into their account', async () => {
      await expect(login<any>(testUser))
            .resolves
            .toMatchObject({ code: 200, success: true })
    })

    it('Ensures the server returns an authenticated status result', async () => {
      const { status } = await getAccStatus();
      expect(status)
          .toMatchObject({ 
              authenticated: true, 
              is_local_account: true 
          });
    })

    it('Ensures the server supports mfa', async () => {
       const { rpc_methods } = await getAccStatus();
        expect(isEnabled({rpc_methods}))
          .toBe(true);
    })
})

describe('When a user wants to add a totp key', () => {

    const { enable, disable } = useTotpApi({ sendRequest })

    it('Ensures the server supports totp', async () => {
      await expect(getData())
            .resolves
            .toMatchObject({ supported_methods: expect.arrayContaining(['totp']) })
    })

    it('Requires a password to enable totp', async () => {``
        await expect(enable({}))
            .rejects
            .toMatchObject({ response: { status: 200, data: { code: 200, success: false } } })
    })

    it('Ensures that a bad password fails to enable totp', async () => {
      await expect(enable({ password: 'badpassword' }))
            .rejects
            .toMatchObject({ response: { status: 200, data: { code: 200, success: false } } })
    })

    it('Enables totp for the user', async () => {
      await expect(enable(testUser))
            .resolves
            .toMatchObject({ digits: 6, period: 30 })
    })

    it('Ensures totp is enabled', async () => {
      await expect(getData())
            .resolves
            .toMatchObject({ methods: [ { type: 'totp', enabled: true } ]})
    })

    it('Disables totp for the user', async () => {
      await expect(disable(testUser))
            .resolves
            .toMatchObject({ code: 200, success: true })
    })

    it('Ensures totp is disabled', async () => {
      await expect(getData())
            .resolves
            .toMatchObject({ methods: []})
    })
})

describe('When a user wants to add a PKOTP public key' , () => {

    const { addOrUpdate, removeKey, disable } = useOtpApi({ sendRequest })
    const testJWK = {
        "kty": "EC",
        "crv": "P-256",
        "kid": "J0iit8NvM4XNkDTRxSo1sOiyoWs=",
        "x": "UoeWn92mwZrEjCARvjDoCcSWeJfBh3JhKLET8mpD4Ck",
        "y": "KLVfgvN05TXnL5U9pV1EQkb3A25qTCwF35gGavt9gss",
        "alg": "ES256"
    }

    it('Ensures the server supports pkotp', async () => {
      await expect(getData())
            .resolves
            .toMatchObject({ supported_methods: expect.arrayContaining(['pkotp']) })
    })

    it('Adds a public key to the account', async () => {
       await expect(addOrUpdate(testJWK, testUser))
            .resolves
            .toMatchObject({ code: 200, success: true })

       await expect(getData())
            .resolves
            .toMatchObject({ methods: [ { type: 'pkotp', enabled: true } ]})
    })

    it('Nothing happens when a user Accidentally adds the same public key', async () => {
        await expect(addOrUpdate(testJWK, testUser))
              .resolves
              .toMatchObject({ code: 200, success: true })
  
        await expect(getData())
              .resolves
              .toMatchObject({ methods: [ { type: 'pkotp', enabled: true, data: { keys: [ testJWK ]} } ]})
    })

    it('Removes the public key from the account', async () => {
        await expect(removeKey(testJWK, testUser))
            .resolves
            .toMatchObject({ code: 200, success: true })

        await expect(getData())
            .resolves
            .toMatchObject({ methods: []})
    })

     it('Disables all keys', async () => {
       await expect(addOrUpdate(testJWK, testUser))
            .resolves
            .toMatchObject({ code: 200, success: true })

       await expect(getData())
            .resolves
            .toMatchObject({ methods: [ { type: 'pkotp', enabled: true, data: { keys: [ testJWK ]} } ]})

        await expect(disable(testUser))
            .resolves
            .toMatchObject({ code: 200, success: true })

        await expect(getData())
            .resolves
            .toMatchObject({ methods: []})
    })
})

describe('When a user wants to enable WebAuthn' , () => {

    const { registerDefaultDevice, disableDevice, disableAllDevices } = useFidoApi({ sendRequest })

    it('Ensures the server supports pkotp', async () => {
      await expect(getData())
            .resolves
            .toMatchObject({ supported_methods: expect.arrayContaining(['fido']) })
    })

   //TODO - Support webauthn registration for automatic browser testing
})

describe('When a user has completed the mfa setup', () => {
    it('Logs the user out of their account', async () => {
      await expect(logout())
            .resolves
            .toMatchObject({ code: 200, success: true })
    })
})
