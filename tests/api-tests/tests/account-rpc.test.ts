import { describe, expect, it } from 'vitest';

import { useAccountRpc } from '@vnuge/vnlib.browser'

const { getData, exec } = useAccountRpc()

describe('List rpc methods', () => {
    it('Gets enabled rpc methods from the server', async () => {
        const { rpc_methods } = await getData();

        // During testing, for now, there may be more methods than expected, 
        // but the expected methods should be present
        expect(rpc_methods)
            .toStrictEqual(expect.arrayContaining([
            {
                "method": "logout",
                "options": []
            },
            {
                "method": "login",
                "options": []
            },
            {
                "method": "mfa.get",
                "options": [ "auth_required" ]
            },
            {
                "method": "mfa.login",
                "options": []
            },
            {
                "method": "mfa.rpc",
                "options": [ "auth_required" ]
            },
            {
                "method": "otp.login",
                "options": []
            },
            {
                "method": "profile.get",
                "options": [ "auth_required" ]
            },
            {
                "method": "profile.update",
                "options": [ "auth_required" ]
            },
            {
                "method": "password.reset",
                "options": [ "auth_required" ]
            },
            {
                "method": "heartbeat",
                "options": [ "auth_required" ]
            }
        ]));
    })
})

const errorResponse = { response: { data: { success: false, code: 401, result: 'You are not logged in' } } }

describe('When a user is not logged in', () => {
    it('Returns 401 errors to protected enpoints', async () => {
      await expect(exec('mfa.get'))
            .rejects
            .toMatchObject(errorResponse)

      await expect(exec('mfa.rpc'))
            .rejects
            .toMatchObject(errorResponse)

      await expect(exec('profile.get'))
            .rejects
            .toMatchObject(errorResponse)

      await expect(exec('profile.update'))
            .rejects
            .toMatchObject(errorResponse)

      await expect(exec('password.reset'))
            .rejects
            .toMatchObject(errorResponse)

      await expect(exec('heartbeat'))
            .rejects
            .toMatchObject(errorResponse)
    })
})