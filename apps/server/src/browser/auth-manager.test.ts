import { describe, it, expect, afterEach } from 'vitest';
import { AuthProfileManager, type PlaywrightStorageState } from './auth-manager.js';

describe('AuthProfileManager', () => {
  const testProfileName = 'test-oauth-session';

  afterEach(async () => {
    await AuthProfileManager.deleteProfile(testProfileName).catch(() => {});
    await AuthProfileManager.deleteProfile('test-jwt-profile').catch(() => {});
  });

  it('saves and loads a valid Playwright storageState profile', async () => {
    const mockState: PlaywrightStorageState = {
      cookies: [
        {
          name: 'oauth_session_id',
          value: 'sess_abc123xyz',
          domain: '127.0.0.1',
          path: '/',
          expires: Math.floor(Date.now() / 1000) + 3600,
          httpOnly: true,
          secure: true,
          sameSite: 'Lax',
        },
      ],
      origins: [
        {
          origin: 'http://127.0.0.1:3000',
          localStorage: [{ name: 'auth_token', value: 'mock.jwt.token' }],
        },
      ],
    };

    const saved = await AuthProfileManager.saveProfile(testProfileName, mockState, {
      description: 'Test OAuth Profile',
      origin: 'http://127.0.0.1:3000',
    });

    expect(saved.name).toBe(testProfileName);
    expect(saved.path).toContain('test-oauth-session.json');

    const loaded = await AuthProfileManager.loadProfile(testProfileName);
    expect(loaded).not.toBeNull();
    expect(loaded?.cookies.length).toBe(1);
    expect(loaded?.cookies[0].name).toBe('oauth_session_id');
    expect(loaded?.origins.length).toBe(1);
    expect(loaded?.origins[0].localStorage[0].value).toBe('mock.jwt.token');
  });

  it('lists existing profiles with metadata', async () => {
    const mockState: PlaywrightStorageState = {
      cookies: [],
      origins: [
        {
          origin: 'http://127.0.0.1:3000',
          localStorage: [{ name: 'access_token', value: 'token123' }],
        },
      ],
    };

    await AuthProfileManager.saveProfile(testProfileName, mockState);
    const profiles = await AuthProfileManager.listProfiles();

    const found = profiles.find((p) => p.name === testProfileName || p.slug === testProfileName);
    expect(found).toBeDefined();
    expect(found?.cookieCount).toBe(0);
    expect(found?.localStorageCount).toBe(1);
  });

  it('creates a bearer token profile for direct JWT auth', async () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_use';
    const result = await AuthProfileManager.createBearerProfile(
      'test-jwt-profile',
      'http://127.0.0.1:3000',
      jwt
    );

    expect(result.name).toBe('test-jwt-profile');
    const loaded = await AuthProfileManager.loadProfile('test-jwt-profile');
    expect(loaded).not.toBeNull();
    expect(loaded?.origins[0].origin).toBe('http://127.0.0.1:3000');
    expect(loaded?.origins[0].localStorage.some((item) => item.value === jwt)).toBe(true);
  });

  it('deletes a profile properly', async () => {
    const mockState: PlaywrightStorageState = { cookies: [], origins: [] };
    await AuthProfileManager.saveProfile(testProfileName, mockState);

    const deleted = await AuthProfileManager.deleteProfile(testProfileName);
    expect(deleted).toBe(true);

    const check = await AuthProfileManager.loadProfile(testProfileName);
    expect(check).toBeNull();
  });
});

