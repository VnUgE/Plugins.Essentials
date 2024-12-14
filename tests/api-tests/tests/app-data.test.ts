import { describe, expect, it } from 'vitest';

import { useAccount, useSession, useAppDataApi } from '@vnuge/vnlib.browser'
const { isLoggedIn } = useSession();
const { login, logout } = useAccount()

const appData = useAppDataApi('/app-data')

const testUser = { userName: 'test@test.com', password: 'Password12!' }

interface TestAppData {
    str: string
    num: number
    bool: boolean
}

const testData: TestAppData = { str: 'test', num: 1, bool: true }

describe('Before a user accesses app-data', () => {
    it('Logs the user into their account', async () => {
      await expect(login<any>(testUser))
            .resolves
            .toMatchObject({ code: 200, success: true })
    })
})

describe('When a user wants to read or write app-data', () => {

    it('Ensures the user is logged in', async () => {
        await expect(isLoggedIn())
            .resolves
            .toBe(true)
    })

    it('Fails to access a scope that does not exist', async () => {
        await expect(appData.get<TestAppData>('bad-scope'))
            .rejects
            .toMatchObject({ response: { data : { success: false, errors: [ 'Invalid scope' ] }}})

        await expect(appData.set('bad-scope', testData))
            .rejects
            .toMatchObject({ response: { data : { success: false, errors: [ 'Invalid scope' ] }}})

        await expect(appData.remove('bad-scope'))
            .rejects
            .toMatchObject({ response: { data : { success: false, errors: [ 'Invalid scope' ] }}})
    })

    it('Modifies app-data', async () => {
        //Data should not exist yet, so we expect undefined
        await expect(appData.get<TestAppData>('test', { noCache: true }))
            .resolves
            .toBe(undefined)

        await expect(appData.set<TestAppData>('test', testData, { wait: true }))
            .resolves
            .toBe(undefined)

        //Data should now exist (cached if configured)
        await expect(appData.get<TestAppData>('test'))
            .resolves
            .toStrictEqual(testData)
    })

    it('Deletes app-data', async () => {
        await expect(appData.remove('test'))
            .resolves
            .toBe(undefined)

        //Data should no longer exist when cache is bypassed
        await expect(appData.get<TestAppData>('test', { noCache: true }))
            .resolves
            .toBe(undefined)
    })

})

describe('When a user has completed the app-data modification', () => {
    it('Logs the user out of their account', async () => {
      await expect(logout())
            .resolves
            .toMatchObject({ code: 200, success: true })
    })
})
