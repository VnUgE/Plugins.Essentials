import { describe, expect, it } from 'vitest';

import { useAccount, useAccountRpc, useSession } from '@vnuge/vnlib.browser'
const { isLoggedIn } = useSession()
const { login, logout, getProfile, resetPassword } = useAccount()
const { getData } = useAccountRpc()

const testUser = { userName: 'test@test.com', password: 'Password12!' }

describe('When a user wants to log in', () => {

    it('Logs in the user', async () => {
      await expect(login<any>(testUser))
            .resolves
            .toMatchObject({ code: 200, success: true })
    })

    it('Ensures the server returns an authenticated status result', async () => {
      const { status } = await getData();
      expect(status)
          .toMatchObject({ 
                  authenticated: true, 
                  is_local_account: true 
            });
    })

    it('Fails to log the user in again', async () => {
      await expect(login<any>(testUser))
            .rejects
            .toMatchObject({ response: { data: { code: 409, success: false }}})
    })
})

describe('When a user accesss their profile information', () => {

    it('Ensures the user is logged in', async () => {
      await expect(isLoggedIn())
            .resolves
            .toBe(true)
    })

    it('Gets the user profile data object', async () => {
      await expect(getProfile())
            .resolves
            .toMatchObject({ email: 'test@test.com' })
    })
})

describe('When a user wants to reset their password', () => {

    it('Ensures the user is logged in', async () => {
      await expect(isLoggedIn())
            .resolves
            .toBe(true)
    })

    it('Submits a password reset', async () => {
      await expect(resetPassword(testUser.password, 'Password123!', {}))
            .resolves
            .toMatchObject({ success: true })
    })

    it('Fails if the old password is used', async () => {
      await expect(resetPassword(testUser.password, 'Password123!', {}))
            .resolves
            .toMatchObject({ success: false })
    })

    //Change password back
    it('Changes the password back', async () => {
      await expect(resetPassword('Password123!', testUser.password, {}))
            .resolves
            .toMatchObject({ success: true })
    })

    //The changed password should fail now
    it('Fails with the old password', async () => {
      await expect(resetPassword('Password123!', testUser.password, {}))
            .resolves
            .toMatchObject({ success: false })
    })
})

describe('When a user has completed account modifications', () => {

      it('Logs the user out', async () => {
        await expect(logout())
              .resolves
              .toMatchObject({ code: 200, success: true })
      })

      it('Ensures the server returns a non-authenticated status result', async () => {
          const { status } = await getData();

          expect(status).toMatchObject({ authenticated: false });
      })
})