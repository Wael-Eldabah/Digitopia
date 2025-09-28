export const backendOrigin = (() => {
  const envOrigin = import.meta.env.VITE_BACKEND_ORIGIN;
  if (envOrigin) {
    return envOrigin.replace(/\/$/, '');
  }
  if (typeof window !== 'undefined') {
    if (import.meta.env.DEV) {
      return 'http://localhost:8000';
    }
    return window.location.origin.replace(/\/$/, '');
  }
  return '';
})();

const ABSOLUTE_PATTERN = /^(?:[a-z]+:)?\/\//i;

export function resolveAssetUrl(path) {
  if (!path) {
    return '';
  }
  if (path.startsWith('blob:') || path.startsWith('data:') || ABSOLUTE_PATTERN.test(path)) {
    return path;
  }
  if (!backendOrigin) {
    return path;
  }
  if (path.startsWith('/')) {
    return `${backendOrigin}${path}`;
  }
  return `${backendOrigin}/${path}`;
}

export function hydrateUserProfile(user) {
  if (!user) {
    return user;
  }
  const resolved = resolveAssetUrl(user.profile_image_url);
  if (resolved === user.profile_image_url) {
    return user;
  }
  return { ...user, profile_image_url: resolved };
}
