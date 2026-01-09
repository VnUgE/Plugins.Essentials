import { describe, expect, it } from 'vitest';

import { useAccountRpc, useOauthLogin } from '@vnuge/vnlib.browser'
import { vnlib } from '../../fixtures';

describe('OAuth Login - E2E Tests', () => {

  const { getData } = useAccountRpc(vnlib)
  const { getPortals, isEnabled } = useOauthLogin(vnlib);

  describe('Social OAuth', () => {
    it('should get the list of social login portals', async () => {
      const accData = await getData();

      expect(isEnabled(accData))
        .toBe(true);

      expect(getPortals(accData))
        .toBeDefined();
    });
  });
});