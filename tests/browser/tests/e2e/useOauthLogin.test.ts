import { describe, expect, it } from 'vitest';

import { useAccountRpc, useOauthLogin } from '@vnuge/vnlib.browser'
import { vnlib } from '../../fixtures';

describe('OAuth Login - E2E Tests', () => {

  const { getData } = useAccountRpc(vnlib)
  const { getPortals, isEnabled, beginLoginFlow } = useOauthLogin(vnlib);

  describe('Social OAuth - Server Configuration', () => {

    it('should check if social OAuth is enabled', async () => {
      const accData = await getData();
      const enabled = isEnabled(accData);

      expect(enabled).toBeTruthy();
    });

    it('should get the list of social login portals', async () => {
      const accData = await getData();
      const portals = getPortals(accData);

      expect(portals).toBeDefined();
      expect(Array.isArray(portals)).toBe(true);
    });

    it('should validate portal structure if any are configured', async () => {
      const accData = await getData();
      const portals = getPortals(accData);

      // If portals exist, validate their structure
      if (portals.length > 0) {
        const portal = portals[0];

        expect(portal).toHaveProperty('method_id');
        expect(portal).toHaveProperty('supported');
        expect(portal).toHaveProperty('data');
        expect(portal.data).toHaveProperty('enabled');
        expect(portal.data).toHaveProperty('friendly_name');

        expect(typeof portal.method_id).toBe('string');
        expect(typeof portal.supported).toBe('boolean');
        expect(typeof portal.data.enabled).toBe('boolean');
        expect(typeof portal.data.friendly_name).toBe('string');
      }
    });

    it('should return all configured portals (enabled and disabled)', async () => {
      const accData = await getData();
      const portals = getPortals(accData);

      // All returned portals should be supported by the server
      portals.forEach(portal => {
        expect(portal.supported).toBe(true);
        // Note: data.enabled can be true or false - server returns all configured portals
        expect(typeof portal.data.enabled).toBe('boolean');
      });
    });
  });

  describe('Social OAuth - Login Flow API', () => {

    it('should have beginLoginFlow method with correct signature', () => {
      expect(typeof beginLoginFlow).toBe('function');
    });

    it('should generate auth URL without auto-redirect', async () => {
      const accData = await getData();
      const portals = getPortals(accData);

      // Skip if no portals configured
      if (portals.length === 0) {
        return;
      }

      const testPortal = portals[0];

      // Test with autoRedirect: false to get URL without redirecting
      const result = await beginLoginFlow({
        method: testPortal,
        autoRedirect: false
      });

      expect(result).toHaveProperty('authUrl');
      expect(typeof result.authUrl).toBe('string');
      expect(result.authUrl.length).toBeGreaterThan(0);

      // Should be a valid URL
      expect(() => new URL(result.authUrl)).not.toThrow();
    });

    it('should generate different auth URLs for different portals', async () => {
      const accData = await getData();
      const portals = getPortals(accData);

      // Skip if less than 2 portals configured
      if (portals.length < 2) {
        return;
      }

      const result1 = await beginLoginFlow({
        method: portals[0],
        autoRedirect: false
      });

      const result2 = await beginLoginFlow({
        method: portals[1],
        autoRedirect: false
      });

      // Different portals should generate different URLs
      expect(result1.authUrl).not.toBe(result2.authUrl);
    });
  });

  describe('Social OAuth - Type Validation', () => {

    it('should maintain proper TypeScript types', async () => {
      const accData = await getData();

      // Type checks - these will fail at compile time if types are wrong
      const enabled: boolean = isEnabled(accData);
      const portals: Array<any> = getPortals(accData);

      expect(enabled).toBeDefined();
      expect(portals).toBeDefined();
    });
  });
});