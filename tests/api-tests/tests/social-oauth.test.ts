import { describe, expect, it } from 'vitest';

import { useAccountRpc, useOauthLogin, useSession } from '@vnuge/vnlib.browser'
const { getData } = useAccountRpc()

const { getPortals, isEnabled } = useOauthLogin();

describe('Social OAuth', () => {
    it('should get the list of social login portals', async () => {
        const accData = await getData();

        expect(isEnabled(accData))
          .toBe(true);
          
        expect(getPortals(accData))
          .toBeDefined();
    });
});