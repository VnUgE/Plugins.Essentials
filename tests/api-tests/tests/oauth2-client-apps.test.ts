import { describe, expect, it, test } from 'vitest';
import { applications, scopes } from "../../../plugins/VNLib.Plugins.Essentials.Oauth.ClientApps/src/Essentials.Oauth.ClientApps.json"
import { useAccount, useAccountRpc, useAxios } from '@vnuge/vnlib.browser'
const { getData } = useAccountRpc()
const { login, logout } = useAccount()

const testUser = { userName: 'test@test.com', password: 'Password12!' }
const testApp = { name: 'Test App', description: 'This is a test app', permissions: "account:read,account:write" }
const axios = useAxios()

export interface OAuth2Application {
    readonly Id: string,
    readonly name: string,
    readonly description: string,
    readonly permissions: string[],
    readonly client_id: string,
    Created: Date,
    readonly LastModified: Date,
}


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

})

describe('When a user gets their client applications', () => {

    it('Checks application scopes', async () => {
      await expect(axios.get<string[]>(scopes.path))
        .resolves
        .toMatchObject({ status: 200, data: scopes.scopes })
    })

    it('Gets the client applications', async () => {
        const { data, status } = await axios.get<OAuth2Application[]>(applications.path);

        expect(status).toBe(200);
        expect(data).toMatchObject([]);
    })

    it('Adds a new client application', async () => {
        await expect(axios.post<OAuth2Application>(`${applications.path}?action=create`, { ...testApp }))
            .resolves
            .toMatchObject({ status: 201, data: {
                name: testApp.name,
                raw_secret: expect.any(String),
            }})
    })

    it('Gets the client applications after adding a new one', async () => {
        await expect(axios.get<OAuth2Application[]>(applications.path))
            .resolves
            .toMatchObject({ 
                status: 200, 
                data: expect.arrayContaining([ expect.objectContaining(testApp) ]) 
            })
    })

    it('tests for illegal characters in fields', async () => {

        const illegal1 = axios.post<OAuth2Application>(`${applications.path}?action=create`, { 
            name: "Illegal app !*", 
            description: "This is a test app", 
            permissions: "account:read,account:write" 
        });

        const illegal2 = axios.post<OAuth2Application>(`${applications.path}?action=create`,{
            name: "Test App", 
            description: "This is a test ** app", 
            permissions: "account:read,account:write"
        })

        const illegal3 = axios.post<OAuth2Application>(`${applications.path}?action=create`,{
            name: "Test App", 
            description: "This is a test app", 
            permissions: "account:read,account:w*rite,account:delete"
        })

        await expect(illegal1)
            .rejects
            .toMatchObject({ response: { status: 422 }})

        await expect(illegal2)
            .rejects
            .toMatchObject({ response: { status: 422 } })

        await expect(illegal3)
            .rejects
            .toMatchObject({ response: { status: 422 } })
    })

    it('Gets the test application by its id', async () => {
        const apps = await axios.get<OAuth2Application[]>(applications.path)
        const app = apps.data.find(a => a.name === testApp.name)
        if (!app) return expect.fail('Test app not found');
        
        await expect(axios.get(`${applications.path}?Id=${app.Id}`))
            .resolves
            .toMatchObject({ status: 200, data: testApp })
    })

    it('Deletes the client application', async () => {
        const apps = await axios.get<OAuth2Application[]>(applications.path)
        const app = apps.data.find(a => a.name === testApp.name)
        if (!app) return expect.fail('Test app not found');

        await expect(axios.post(`${applications.path}?action=delete`, { password: testUser.password, Id: app.Id }))
            .resolves
            .toMatchObject({ status: 204 })
    })

    it('Ensures the client application was deleted', async () => {
        await expect(axios.get<OAuth2Application[]>(applications.path))
            .resolves
            .toMatchObject({ status: 200, data: expect.not.arrayContaining([testApp]) })
    })
})

describe('When a user has completed oauth2 modifications', () => {

      it('Logs the user out', async () => {
        await expect(logout())
              .resolves
              .toMatchObject({ code: 200, success: true })
      })
})