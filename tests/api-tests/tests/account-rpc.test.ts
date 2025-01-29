import { describe, expect, it } from 'vitest';
import { useAccountRpc } from '@vnuge/vnlib.browser'

const { getData, exec } = useAccountRpc()

describe('List rpc methods', () => {
    it('Gets enabled rpc methods from the server', async () => {
        const { rpc_methods, http_methods, status } = await getData();

        expect(status)
            .toMatchObject({
                authenticated: false,
                is_local_account: false
            })

        expect(http_methods)
            .toEqual(['POST', 'GET']);

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

describe('The server should return some required extented properties', () => {

    it('Returns login information if the login command is present', async () => {
        const { rpc_methods, properties } = await getData();
     
        if(rpc_methods.find(method => method.method === 'login')){

            const loginProperty = properties.find(property => property.type === 'login');

            expect(loginProperty)
                .toMatchObject({
                    type: "login",
                    enforce_email: true,
                    username_max_chars: 64,
                })
        }
    })
})