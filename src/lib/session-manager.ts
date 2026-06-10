/**
 * Shared Session Manager for VIP-Intelligence
 *
 * Provides resilient session checking with:
 * - sessionStorage caching to avoid redundant server calls
 * - Retry logic for transient errors
 * - Only redirects to login on explicit 401 (not on server errors)
 */

export interface AuthUser {
  id: string;
  name: string;
  email: string;
  role: string;
  mfaEnabled: boolean;
}

const SESSION_CACHE_KEY = 'vip_auth_user';
const SESSION_CACHE_TIMESTAMP_KEY = 'vip_auth_timestamp';
const SESSION_CACHE_TTL = 5 * 60 * 1000; // 5 minutes cache TTL

/**
 * Get cached user from sessionStorage if still valid
 */
export function getCachedUser(): AuthUser | null {
  if (typeof window === 'undefined') return null;

  try {
    const cached = sessionStorage.getItem(SESSION_CACHE_KEY);
    const timestamp = sessionStorage.getItem(SESSION_CACHE_TIMESTAMP_KEY);

    if (!cached || !timestamp) return null;

    const age = Date.now() - parseInt(timestamp, 10);
    if (age > SESSION_CACHE_TTL) {
      // Cache expired, clear it
      sessionStorage.removeItem(SESSION_CACHE_KEY);
      sessionStorage.removeItem(SESSION_CACHE_TIMESTAMP_KEY);
      return null;
    }

    return JSON.parse(cached) as AuthUser;
  } catch {
    return null;
  }
}

/**
 * Save user to sessionStorage cache
 */
export function setCachedUser(user: AuthUser): void {
  if (typeof window === 'undefined') return;

  try {
    sessionStorage.setItem(SESSION_CACHE_KEY, JSON.stringify(user));
    sessionStorage.setItem(SESSION_CACHE_TIMESTAMP_KEY, Date.now().toString());
  } catch {
    // sessionStorage might be full or unavailable, silently ignore
  }
}

/**
 * Clear cached user from sessionStorage
 */
export function clearCachedUser(): void {
  if (typeof window === 'undefined') return;

  try {
    sessionStorage.removeItem(SESSION_CACHE_KEY);
    sessionStorage.removeItem(SESSION_CACHE_TIMESTAMP_KEY);
  } catch {
    // silently ignore
  }
}

/**
 * Check the current session with the server.
 * Returns the authenticated user or null.
 * Only redirects to login on explicit 401 responses.
 * On server errors, returns the cached user if available.
 *
 * @param retries - Number of retries on server error (default 1)
 */
export async function checkSession(retries: number = 1): Promise<AuthUser | null> {
  // First, check the cache
  const cached = getCachedUser();
  if (cached) {
    // We have a valid cache — do a background refresh but return cached immediately
    refreshSessionInBackground();
    return cached;
  }

  // No cache, need to check the server
  return fetchSessionFromServer(retries);
}

/**
 * Fetch session from server with retry logic
 */
async function fetchSessionFromServer(retries: number = 1): Promise<AuthUser | null> {
  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch('/api/auth/session');

      if (res.ok) {
        const data = await res.json();
        const user: AuthUser = data.user;

        // Cache the user
        setCachedUser(user);
        return user;
      }

      if (res.status === 401) {
        // Explicitly unauthorized — session is invalid
        clearCachedUser();
        return null;
      }

      // Other error codes (500, 503, etc.) — don't lose session, retry
      lastError = new Error(`Server returned ${res.status}`);

      if (attempt < retries) {
        // Wait before retrying (exponential backoff)
        await new Promise(r => setTimeout(r, 500 * (attempt + 1)));
        continue;
      }
    } catch (error) {
      // Network error — don't lose session if we have cache
      lastError = error instanceof Error ? error : new Error(String(error));

      if (attempt < retries) {
        await new Promise(r => setTimeout(r, 500 * (attempt + 1)));
        continue;
      }
    }
  }

  // All retries failed — if we had a cache, don't log out
  // The user is probably just experiencing connectivity issues
  console.warn('[Session] Server unreachable after retries, session may be stale');
  return null;
}

/**
 * Background session refresh — doesn't block the UI
 */
let refreshInProgress = false;

async function refreshSessionInBackground(): Promise<void> {
  if (refreshInProgress) return;
  refreshInProgress = true;

  try {
    const res = await fetch('/api/auth/session');

    if (res.ok) {
      const data = await res.json();
      setCachedUser(data.user);
    } else if (res.status === 401) {
      // Session is truly invalid — clear cache
      clearCachedUser();
      // Redirect to login
      window.location.href = '/auth/login';
    }
    // Other errors — keep the cached session
  } catch {
    // Network error — keep the cached session
  } finally {
    refreshInProgress = false;
  }
}

/**
 * Resilient session check for page components.
 * Returns the user and a loading state.
 * Only redirects to login on explicit 401, not on server errors.
 */
export async function requireSession(): Promise<{ user: AuthUser; redirect: false } | { user: null; redirect: true }> {
  const user = await checkSession(2);

  if (user) {
    return { user, redirect: false };
  }

  // No user from server or cache — redirect to login
  clearCachedUser();
  return { user: null, redirect: true };
}
