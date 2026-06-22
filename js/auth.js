// ============================================================
// VHLC — Authentication Module (auth.js)
// Handles: Login, Logout, Role Routing, Session Guards
// ============================================================

// ── Login ──────────────────────────────────────────────────
async function loginUser(email, password) {
  const userCredential = await auth.signInWithEmailAndPassword(email, password);
  return userCredential.user;
}

// ── Logout ─────────────────────────────────────────────────
async function logoutUser() {
  await auth.signOut();
  window.location.href = getRootPath() + 'login.html';
}

// ── Get User Role from Firestore ────────────────────────────
async function getUserRole(uid) {
  const doc = await db.collection('users').doc(uid).get();
  if (!doc.exists) throw new Error('User profile not found.');
  const data = doc.data();
  if (data.isActive === false) {
    await auth.signOut();
    throw new Error('Your account has been disabled. Contact the administrator.');
  }
  return data.role; // 'admin' | 'teacher' | 'student'
}

// ── Redirect by Role ────────────────────────────────────────
function redirectByRole(role) {
  const root = getRootPath();
  const cleanRole = (role || '').toString().toLowerCase().trim();
  const map = {
    admin:   root + 'admin/dashboard.html',
    teacher: root + 'teacher/dashboard.html',
    student: root + 'student/dashboard.html',
  };
  
  if (map[cleanRole]) {
    window.location.replace(map[cleanRole]);
  } else {
    console.error('Invalid user role:', role);
    auth.signOut().then(() => {
      window.location.replace(root + 'login.html?error=invalid_role');
    });
  }
}

// ── Guard: Require Authentication ───────────────────────────
// Call at top of every protected page.
// requiredRole: 'admin' | 'teacher' | 'student' | null (any auth)
function requireAuth(requiredRole = null) {
  return new Promise((resolve, reject) => {
    const unsubscribe = auth.onAuthStateChanged(async (user) => {
      unsubscribe();
      if (!user) {
        window.location.href = getRootPath() + 'login.html';
        return reject('Not authenticated');
      }
      try {
        const role = await getUserRole(user.uid);
        if (requiredRole && role !== requiredRole) {
          // Wrong role — redirect to correct portal
          redirectByRole(role);
          return reject('Wrong role');
        }
        resolve({ user, role });
      } catch (err) {
        showToast(err.message, 'error');
        setTimeout(() => {
          window.location.href = getRootPath() + 'login.html';
        }, 2000);
        reject(err);
      }
    });
  });
}

// ── Guard: Redirect If Already Logged In (for login page) ───
function redirectIfLoggedIn() {
  auth.onAuthStateChanged(async (user) => {
    if (user) {
      try {
        const role = await getUserRole(user.uid);
        redirectByRole(role);
      } catch (_) {
        // ignore — user will stay on login page
      }
    }
  });
}

// ── Get Root Path (works from subdirectories) ───────────────
function getRootPath() {
  const path = window.location.pathname;
  if (path.includes('/admin/') || path.includes('/student/') || path.includes('/teacher/')) {
    return '../';
  }
  return './';
}

// ── Get Current Auth User ────────────────────────────────────
function getCurrentUser() {
  return auth.currentUser;
}

// ── Admin: Create User Account ──────────────────────────────
// Uses Firebase Admin SDK is NOT available on client.
// Instead, we create via a secondary app instance so the
// admin doesn't get logged out.
async function adminCreateUser(email, password, profileData) {
  // Create secondary app to avoid signing out current admin
  const secondaryApp = firebase.initializeApp(firebase.app().options, 'Secondary_' + Date.now());
  const secondaryAuth = secondaryApp.auth();

  try {
    const cred = await secondaryAuth.createUserWithEmailAndPassword(email, password);
    const uid  = cred.user.uid;

    // Write to Firestore users collection
    await db.collection('users').doc(uid).set({
      uid,
      email,
      role:      profileData.role,
      isActive:  true,
      createdAt: firebase.firestore.FieldValue.serverTimestamp(),
    });

    // Write to role-specific collection
    const collection = profileData.role === 'student' ? 'students' : 'teachers';
    await db.collection(collection).doc(uid).set({
      uid,
      ...profileData,
      createdAt: firebase.firestore.FieldValue.serverTimestamp(),
    });

    await secondaryAuth.signOut();
    return uid;
  } finally {
    await secondaryApp.delete();
  }
}

// ── Admin: Disable / Enable User ────────────────────────────
async function setUserStatus(uid, isActive) {
  await db.collection('users').doc(uid).update({ isActive });
}

// ── Change Password ──────────────────────────────────────────
async function changePassword(newPassword) {
  const user = auth.currentUser;
  if (!user) throw new Error('Not authenticated');
  await user.updatePassword(newPassword);
}
