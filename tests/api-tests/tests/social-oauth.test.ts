import { describe, expect, it } from 'vitest';

import { useAccountRpc, useOauthLogin, useSession } from '@vnuge/vnlib.browser'
const { getData } = useAccountRpc()

const { getPortals } = useOauthLogin(getData);

describe('Social OAuth', () => {
    it('should get the list of social login portals', async () => {
        
        const portals = await getPortals();
        expect(portals).toBeDefined();
        

    });
});