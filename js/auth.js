// Store the last auth check timestamp to prevent rapid rechecks
let lastAuthCheck = 0;
const AUTH_CHECK_INTERVAL = 1000; // Minimum 1 second between checks

// Session storage key for auth cache
const AUTH_CACHE_KEY = 'mismo_auth_cache';

// Loading state to prevent redirects while Firebase initializes
let isAuthLoading = true;
// Keep the unsubscribe function so we can clean up observer listeners
let authObserverUnsubscribe = null;
// Ensure the observer redirect logic runs only once per page load
let authObserverHasRunOnce = false;

function initAuthObserver() {
    if (authObserverUnsubscribe) return;
    if (typeof firebase === 'undefined' || !firebase.auth) {
        console.warn('[auth] firebase not available yet for initAuthObserver');
        return;
    }

    authObserverUnsubscribe = firebase.auth().onAuthStateChanged((user) => {
        try {
            console.log('[auth] auth observer:', user ? user.email : null);

            // After the first invocation, we consider initial loading finished
            if (isAuthLoading) {
                isAuthLoading = false;
                window.isAuthLoading = false;
            }

            // Clear cached auth when signed out
            if (!user) {
                sessionStorage.removeItem(AUTH_CACHE_KEY);
            } else {
                // Warm up cache (non-blocking)
                checkAuth().catch((e) => console.warn('[auth] preload checkAuth failed', e));
            }

            // One-time redirect decision: run only once to prevent loops
            if (!authObserverHasRunOnce) {
                authObserverHasRunOnce = true;

                const currentPath = window.location.pathname.toLowerCase();
                const isLoginPage = currentPath.includes('login.html');
                const isUserPage = currentPath.includes('user.html');
                const isAdminPage = currentPath.includes('admin.html');

                const now = Date.now();
                const sharedLast = window.lastRedirectTime || lastRedirectTime || 0;
                const canRedirect = (!isAuthLoading) && (now - sharedLast > REDIRECT_COOLDOWN);

                // If on login page and we have a signed-in user, redirect once to their page
                if (isLoginPage && user && canRedirect) {
                    lastRedirectTime = now;
                    window.lastRedirectTime = lastRedirectTime;
                    // Fetch profile to determine userType
                    firebase.firestore().collection('users').doc(user.uid).get()
                        .then(doc => {
                            const userData = doc.exists ? doc.data() : null;
                            if (userData && userData.userType) {
                                window.location.href = userData.userType === 'admin' ? 'admin.html' : 'user.html';
                            }
                        }).catch(err => console.warn('[auth] failed fetching profile for redirect', err));
                }

                // If on user/admin page and userType mismatch, redirect to correct page once
                if ((isUserPage || isAdminPage) && user && canRedirect) {
                    // Warm up cache then check
                    checkAuth().then(({ userData }) => {
                        if (!userData) return;
                        if (userData.userType === 'admin' && !isAdminPage) {
                            lastRedirectTime = now;
                            window.lastRedirectTime = lastRedirectTime;
                            window.location.href = 'admin.html';
                        } else if (userData.userType === 'user' && !isUserPage) {
                            lastRedirectTime = now;
                            window.lastRedirectTime = lastRedirectTime;
                            window.location.href = 'user.html';
                        }
                    }).catch(() => {});
                }
            }
        } catch (e) {
            console.warn('[auth] auth observer handler error', e);
        }
    });
}

function cleanupAuthObserver() {
    try {
        if (authObserverUnsubscribe) {
            authObserverUnsubscribe();
            authObserverUnsubscribe = null;
        }
    } catch (e) {
        console.warn('[auth] error cleaning up observer', e);
    }
    isAuthLoading = false;
    window.isAuthLoading = false;
}

// Check authentication state (non-redirecting)
// This function now returns the current auth state and user profile if available,
// but it does NOT perform any page redirects. Page-level code should call
// `checkUserType()` or perform redirects using the shared cooldown.
async function checkAuth() {
    // Prevent multiple rapid checks
    const now = Date.now();
    if (now - lastAuthCheck < AUTH_CHECK_INTERVAL) {
        console.log('[auth] Skipping auth check - too soon');
        const cachedAuth = sessionStorage.getItem(AUTH_CACHE_KEY);
        if (cachedAuth) {
            return JSON.parse(cachedAuth);
        }
        // fallthrough to a fresh attempt
    }
    lastAuthCheck = now;

    // Try to use synchronous currentUser if available
    const user = firebase.auth().currentUser;
    if (!user) {
        console.log('[auth] No currentUser available');
        // Clear cached auth and return explicit nulls (no redirects here)
        sessionStorage.removeItem(AUTH_CACHE_KEY);
        return { user: null, userData: null };
    }

    try {
        console.log('[auth] Fetching user data for:', user.email);
        const userDoc = await firebase.firestore().collection('users').doc(user.uid).get();
        const userData = userDoc.exists ? userDoc.data() : null;
        const result = { user, userData };
        sessionStorage.setItem(AUTH_CACHE_KEY, JSON.stringify(result));
        return result;
    } catch (error) {
        console.error('[auth] Error fetching user data:', error);
        return { user, userData: null };
    }
}

// Logout function
function logout() {
    firebase.auth().signOut()
        .then(() => {
            window.location.href = 'login.html';
        })
        .catch((error) => {
            console.error('Error signing out:', error);
        });
}

// Track the last redirection to prevent loops
let lastRedirectTime = 0;
const REDIRECT_COOLDOWN = 2000; // 2 seconds between redirects

// Check user type and redirect if necessary
async function checkUserType(allowedType) {
    // Get current path
    const currentPath = window.location.pathname.toLowerCase();
    const isLoginPage = currentPath.includes('login.html');
    const isUserPage = currentPath.includes('user.html');
    const isAdminPage = currentPath.includes('admin.html');

    // Skip check if we're on login page
    if (isLoginPage) return;

    // Determine whether redirecting is allowed based on shared cooldown and loading state
    const now = Date.now();
    const sharedLast = window.lastRedirectTime || lastRedirectTime || 0;
    const canRedirect = (!isAuthLoading) && (now - sharedLast > REDIRECT_COOLDOWN);

    try {
        const { user, userData } = await checkAuth();

        if (!user) {
            console.log('[auth] No signed-in user');
            if (canRedirect) {
                lastRedirectTime = now;
                window.lastRedirectTime = lastRedirectTime;
                window.location.href = 'login.html';
            }
            return;
        }

        if (!userData) {
            console.log('[auth] User profile missing');
            if (canRedirect) {
                lastRedirectTime = now;
                window.lastRedirectTime = lastRedirectTime;
                window.location.href = 'login.html';
            }
            return;
        }

        console.log('[auth] Check type:', {
            current: userData.userType,
            allowed: allowedType,
            path: currentPath,
            canRedirect
        });

        if (userData.userType !== allowedType) {
            if (!canRedirect) return;
            lastRedirectTime = now;
            window.lastRedirectTime = lastRedirectTime;

            if (userData.userType === 'admin' && !isAdminPage) {
                console.log('[auth] Redirecting admin to admin page');
                window.location.href = 'admin.html';
            } else if (userData.userType === 'user' && !isUserPage) {
                console.log('[auth] Redirecting user to user page');
                window.location.href = 'user.html';
            }
        }
    } catch (error) {
        console.error('[auth] checkUserType unexpected error:', error);
        // In case of unexpected error, redirect to login once
        if (canRedirect) {
            lastRedirectTime = now;
            window.lastRedirectTime = lastRedirectTime;
            window.location.href = 'login.html';
        }
    }
}

// Initialize auth observer when DOM is ready so we know Firebase has been loaded
try {
    document.addEventListener('DOMContentLoaded', () => {
        initAuthObserver();
        // expose cleanup for pages that may want to remove the observer
        window.cleanupAuthObserver = cleanupAuthObserver;
    });
} catch (e) {
    // fallback: try to init immediately
    initAuthObserver();
    window.cleanupAuthObserver = cleanupAuthObserver;
}