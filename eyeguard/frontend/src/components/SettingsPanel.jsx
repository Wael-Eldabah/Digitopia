// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useContext, useEffect, useMemo, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import axios from 'axios';
import { AuthContext } from '../App.jsx';

const fetchSettingsData = async () => {
  const [usersResponse, pendingResponse] = await Promise.all([
    axios.get('/api/v1/settings/users'),
    axios.get('/api/v1/settings/users/pending'),
  ]);
  return { users: usersResponse.data, pending: pendingResponse.data };
};

const Toggle = ({ enabled, onChange, disabled }) => (
  <button
    type="button"
    onClick={() => onChange(!enabled)}
    disabled={disabled}
    className={`relative flex h-6 w-12 items-center rounded-full transition ${enabled ? 'bg-emerald-500/80' : 'bg-slate-700/80'} ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
  >
    <span className={`absolute h-5 w-5 rounded-full bg-white shadow transform transition ${enabled ? 'translate-x-6' : 'translate-x-1'}`} />
  </button>
);

const initialsFromName = (name, fallback) => {
  if (!name) {
    return fallback;
  }
  const parts = name.trim().split(/\s+/);
  return parts.slice(0, 2).map((chunk) => chunk[0]?.toUpperCase() || '').join('') || fallback;
};

export default function SettingsPanel() {
  const queryClient = useQueryClient();
  const { user, updateUser, managerPending, setManagerPending, refreshProfile } = useContext(AuthContext);
  const { data, isLoading } = useQuery({ queryKey: ['settings-users'], queryFn: fetchSettingsData });

  const [profileForm, setProfileForm] = useState({
    displayName: user?.display_name || '',
    email: user?.email || '',
    role: user?.role || 'SOC_ANALYST',
  });
  const [notifications, setNotifications] = useState({
    criticalEmail: user?.notifications?.critical_email ?? true,
    weeklyDigest: user?.notifications?.weekly_digest ?? true,
    push: user?.notifications?.push ?? false,
  });
  const [apiKey, setApiKey] = useState('eyeg-4c1d-7b28-training');
  const [feedback, setFeedback] = useState('');
  const [error, setError] = useState('');
  const [uploadPreview, setUploadPreview] = useState(user?.profile_image_url || '');
  const [uploadError, setUploadError] = useState('');
  const fileInputRef = useRef(null);

  useEffect(() => {
    if (!user) {
      return;
    }
    setProfileForm({
      displayName: user.display_name || '',
      email: user.email,
      role: user.role,
    });
    setNotifications({
      criticalEmail: user.notifications?.critical_email ?? true,
      weeklyDigest: user.notifications?.weekly_digest ?? true,
      push: user.notifications?.push ?? false,
    });
    setUploadPreview(user.profile_image_url || '');
  }, [user]);

  useEffect(() => {
    if (user?.role === 'MANAGER' && data?.pending) {
      setManagerPending(data.pending.length);
    }
  }, [data?.pending, user?.role, setManagerPending]);

  const profileMutation = useMutation({
    mutationFn: (payload) => axios.patch('/api/v1/settings/profile', payload),
    onMutate: () => {
      setFeedback('');
      setError('');
    },
    onSuccess: ({ data: updated }) => {
      updateUser(updated);
      setFeedback('Profile updated successfully.');
    },
    onError: (mutationError) => {
      const message = mutationError?.response?.data?.detail?.message || 'Unable to update profile.';
      setError(message);
    },
  });

  const notificationsMutation = useMutation({
    mutationFn: (payload) => axios.patch('/api/v1/settings/profile/notifications', { notifications: payload }),
    onError: (mutationError) => {
      const message = mutationError?.response?.data?.detail?.message || 'Failed to update notification preferences.';
      setError(message);
    },
    onSuccess: ({ data: updated }) => {
      updateUser(updated);
      setFeedback('Notification preferences saved.');
    },
  });

  const avatarMutation = useMutation({
    mutationFn: () => axios.post('/api/v1/settings/profile/avatar'),
    onSuccess: ({ data: updated }) => {
      updateUser(updated);
      setUploadPreview(updated.profile_image_url || '');
      setFeedback('New avatar generated.');
    },
    onError: () => {
      setError('Unable to generate a new avatar.');
    },
  });

  const uploadMutation = useMutation({
    mutationFn: (file) => {
      const formData = new FormData();
      formData.append('file', file);
      return axios.post('/api/v1/settings/profile/avatar/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
    },
    onError: (err) => {
      const message = err?.response?.data?.error || 'Upload failed. Ensure the image is under 2MB.';
      setUploadError(message);
    },
    onSuccess: ({ data: response }) => {
      setUploadPreview(response.profile_image_url);
      refreshProfile();
      setUploadError('');
      setFeedback('Profile image updated.');
    },
  });

  const approve = useMutation({
    mutationFn: (requestId) => axios.post(`/api/v1/settings/users/${requestId}/approve`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings-users'] });
      refreshProfile();
    },
  });

  const reject = useMutation({
    mutationFn: (requestId) => axios.post(`/api/v1/settings/users/${requestId}/reject`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings-users'] });
      refreshProfile();
    },
  });

  const resetPassword = useMutation({
    mutationFn: ({ userId, newPassword }) => axios.post(`/api/v1/settings/users/${userId}/reset-password`, { new_password: newPassword || undefined }),
    onSuccess: ({ data: response }) => {
      setFeedback(`Password reset. New password: ${response.new_password}`);
    },
    onError: (err) => {
      const message = err?.response?.data?.error || 'Unable to reset password.';
      setError(message);
    },
  });

  const updateStatus = useMutation({
    mutationFn: ({ userId, status }) => axios.post(`/api/v1/settings/users/${userId}/status`, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings-users'] });
      refreshProfile();
    },
    onError: (err) => {
      const message = err?.response?.data?.error || 'Unable to update status.';
      setError(message);
    },
  });

  const deleteUser = useMutation({
    mutationFn: (userId) => axios.delete(`/api/v1/settings/users/${userId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings-users'] });
      refreshProfile();
    },
    onError: (err) => {
      const message = err?.response?.data?.error || 'Unable to delete user.';
      setError(message);
    },
  });

  const regenerateKey = () => {
    const random = Math.random().toString(36).slice(2, 10);
    setApiKey(`eyeg-${random}`);
    setFeedback('New sandbox API key generated.');
  };

  const handleSaveProfile = () => {
    profileMutation.mutate({
      display_name: profileForm.displayName,
      email: profileForm.email,
    });
  };

  const handleToggle = (key, next) => {
    const nextState = { ...notifications, [key]: next };
    setNotifications(nextState);
    notificationsMutation.mutate({
      critical_email: nextState.criticalEmail,
      weekly_digest: nextState.weeklyDigest,
      push: nextState.push,
    });
  };

  const handleFileSelect = (event) => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }
    setUploadError('');
    setUploadPreview(URL.createObjectURL(file));
    uploadMutation.mutate(file);
  };

  const handleUploadClick = () => {
    fileInputRef.current?.click();
  };

  const profileInitials = initialsFromName(profileForm.displayName, initialsFromName(user?.email || 'Analyst', 'EG'));
  const isManager = user?.role === 'MANAGER';

  if (isLoading || !data) {
    return <div className="p-6 text-slate-400">Loading settings...</div>;
  }

  return (
    <div className="grid xl:grid-cols-[2fr_1fr] gap-6">
      <div className="space-y-6">
        <section className="bg-[#101b30] border border-slate-800/70 rounded-3xl p-8 shadow-[0_25px_60px_rgba(8,17,32,0.55)]">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-4">
              {uploadPreview ? (
                <img src={uploadPreview} alt="Profile" className="h-14 w-14 rounded-2xl object-cover border border-slate-700" />
              ) : (
                <div className="h-14 w-14 rounded-2xl flex items-center justify-center text-lg font-semibold text-slate-950 bg-slate-800/70">
                  {profileInitials}
                </div>
              )}
              <div>
                <h3 className="text-lg font-semibold text-slate-100">User Profile</h3>
                <p className="text-xs uppercase tracking-wider text-slate-500">Manage operator identity</p>
              </div>
            </div>
            <div className="flex gap-2">
              <input ref={fileInputRef} type="file" accept="image/*" className="hidden" onChange={handleFileSelect} />
              <button
                type="button"
                onClick={handleUploadClick}
                className="px-3 py-1.5 rounded-xl bg-emerald-500/80 text-slate-950 text-xs font-semibold hover:bg-emerald-400 transition disabled:opacity-60"
                disabled={uploadMutation.isPending}
              >
                {uploadMutation.isPending ? 'Uploading...' : 'Upload Photo'}
              </button>
              <button
                type="button"
                onClick={() => avatarMutation.mutate()}
                className="px-3 py-1.5 rounded-xl bg-sky-500/80 text-slate-950 text-xs font-semibold hover:bg-sky-400 transition disabled:opacity-60"
                disabled={avatarMutation.isPending}
              >
                {avatarMutation.isPending ? 'Generating...' : 'Change Avatar'}
              </button>
            </div>
          </div>
          <div className="mt-6 grid md:grid-cols-2 gap-5 text-sm">
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wide text-slate-500">Full Name</label>
              <input
                value={profileForm.displayName}
                onChange={(event) => setProfileForm((prev) => ({ ...prev, displayName: event.target.value }))}
                className="bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wide text-slate-500">Email Address</label>
              <input
                value={profileForm.email}
                onChange={(event) => setProfileForm((prev) => ({ ...prev, email: event.target.value }))}
                className="bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wide text-slate-500">Role</label>
              <input
                value={profileForm.role.replace('_', ' ')}
                readOnly
                className="bg-slate-900/40 border border-slate-800 rounded-xl px-3 py-2 text-slate-400 uppercase tracking-wide"
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wide text-slate-500">Account State</label>
              <input
                value={user?.status || 'pending'}
                readOnly
                className="bg-slate-900/40 border border-slate-800 rounded-xl px-3 py-2 text-slate-400 uppercase tracking-wide"
              />
            </div>
          </div>
          {(feedback || error || uploadError) && (
            <div className="mt-4 text-xs space-y-1">
              {feedback && <p className="text-emerald-300">{feedback}</p>}
              {error && <p className="text-rose-400">{error}</p>}
              {uploadError && <p className="text-rose-400">{uploadError}</p>}
            </div>
          )}
          <div className="mt-6 flex justify-end">
            <button
              type="button"
              onClick={handleSaveProfile}
              className="px-5 py-2 rounded-xl bg-gradient-to-r from-sky-500 to-emerald-500 text-slate-950 text-sm font-semibold shadow-md shadow-emerald-500/30 hover:from-sky-400 hover:to-emerald-400 transition disabled:opacity-60"
              disabled={profileMutation.isPending}
            >
              {profileMutation.isPending ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </section>

        <section className="bg-[#101b30] border border-slate-800/70 rounded-3xl p-8 shadow-[0_25px_60px_rgba(8,17,32,0.55)] space-y-6">
          <div>
            <h3 className="text-lg font-semibold text-slate-100">Notifications</h3>
            <p className="text-xs uppercase tracking-wider text-slate-500">Fine tune operational communications</p>
          </div>
          <div className="space-y-5 text-sm">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-semibold text-slate-200">Email on Critical Alerts</p>
                <p className="text-xs text-slate-500">Receive real-time notices for high severity findings.</p>
              </div>
              <Toggle enabled={notifications.criticalEmail} onChange={(next) => handleToggle('criticalEmail', next)} disabled={notificationsMutation.isPending} />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-semibold text-slate-200">Weekly Security Digest</p>
                <p className="text-xs text-slate-500">Monday roundup with the top shifts and anomalies.</p>
              </div>
              <Toggle enabled={notifications.weeklyDigest} onChange={(next) => handleToggle('weeklyDigest', next)} disabled={notificationsMutation.isPending} />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-semibold text-slate-200">Push Notifications</p>
                <p className="text-xs text-slate-500">Trigger mobile notifications for escalations.</p>
              </div>
              <Toggle enabled={notifications.push} onChange={(next) => handleToggle('push', next)} disabled={notificationsMutation.isPending} />
            </div>
          </div>
        </section>

        <section className="bg-[#101b30] border border-slate-800/70 rounded-3xl p-8 shadow-[0_25px_60px_rgba(8,17,32,0.55)] space-y-5">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-slate-100">API Keys & Integrations</h3>
              <p className="text-xs uppercase tracking-wider text-slate-500">Manage sandbox credentials</p>
            </div>
            <button
              type="button"
              onClick={regenerateKey}
              className="px-3 py-2 rounded-xl bg-emerald-500/80 text-slate-950 text-xs font-semibold hover:bg-emerald-400 transition"
            >
              Generate New Key
            </button>
          </div>
          <div className="bg-slate-900/70 border border-slate-800 rounded-2xl px-4 py-3 font-mono text-sm text-emerald-300 flex items-center justify-between">
            <span>{apiKey}</span>
            <span className="text-xs text-slate-500 uppercase tracking-wide">Sandbox</span>
          </div>
        </section>
      </div>

      <div className="space-y-6">
        <section className="bg-[#101b30] border border-slate-800/70 rounded-3xl p-6 shadow-[0_25px_60px_rgba(8,17,32,0.55)]">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-slate-100">Active Team</h3>
            {isManager && (
              <span className="text-xs text-emerald-300">Pending: {managerPending}</span>
            )}
          </div>
          <ul className="space-y-4">
            {data.users.map((entry) => (
              <li key={entry.id} className="bg-slate-900/60 border border-slate-800/70 rounded-2xl px-4 py-3 space-y-2">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-slate-100">{entry.display_name || entry.email}</p>
                    <p className="text-xs text-slate-500">{entry.role.replace('_', ' ')} - {entry.status}</p>
                  </div>
                  {entry.profile_image_url ? (
                    <img src={entry.profile_image_url} alt={entry.display_name || entry.email} className="h-9 w-9 rounded-full object-cover border border-slate-700" />
                  ) : (
                    <div className="h-9 w-9 rounded-full bg-slate-800/70 flex items-center justify-center text-[11px] text-slate-300">
                      {initialsFromName(entry.display_name || entry.email, 'EG')}
                    </div>
                  )}
                </div>
                {isManager && entry.id !== user?.id && (
                  <div className="flex flex-wrap gap-2 text-xs">
                    <button
                      type="button"
                      className="px-3 py-1.5 rounded-lg border border-slate-700 hover:border-emerald-400 hover:text-emerald-300 transition"
                      onClick={() => updateStatus.mutate({ userId: entry.id, status: entry.status === 'disabled' ? 'active' : 'disabled' })}
                      disabled={updateStatus.isPending}
                    >
                      {entry.status === 'disabled' ? 'Activate' : 'Deactivate'}
                    </button>
                    <button
                      type="button"
                      className="px-3 py-1.5 rounded-lg border border-slate-700 hover:border-sky-400 hover:text-sky-300 transition"
                      onClick={() => resetPassword.mutate({ userId: entry.id })}
                      disabled={resetPassword.isPending}
                    >
                      Reset Password
                    </button>
                    <button
                      type="button"
                      className="px-3 py-1.5 rounded-lg border border-rose-500 text-rose-300 hover:bg-rose-500/10 transition"
                      onClick={() => deleteUser.mutate(entry.id)}
                      disabled={deleteUser.isPending}
                    >
                      Delete
                    </button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        </section>
        <section className="bg-[#101b30] border border-slate-800/70 rounded-3xl p-6 shadow-[0_25px_60px_rgba(8,17,32,0.55)]">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-slate-100">Pending Approvals</h3>
            <span className="text-xs text-slate-500">Manager review</span>
          </div>
          <div className="space-y-4">
            {data.pending.length === 0 && (
              <p className="text-sm text-slate-500 bg-slate-900/60 border border-slate-800/70 rounded-2xl px-4 py-3">
                No pending requests.
              </p>
            )}
            {data.pending.map((request) => (
              <div key={request.request_id} className="bg-slate-900/60 border border-slate-800/70 rounded-2xl px-4 py-3">
                <div className="flex items-start justify-between">
                  <div>
                    <p className="text-sm font-semibold text-slate-100">{request.email}</p>
                    <p className="text-xs text-slate-500">Requested: {request.role}</p>
                  </div>
                  {isManager ? (
                    <div className="flex gap-2">
                      <button
                        type="button"
                        className="px-3 py-1.5 rounded-xl bg-emerald-500/80 text-slate-950 text-xs font-semibold hover:bg-emerald-400 transition"
                        onClick={() => approve.mutate(request.request_id)}
                        disabled={approve.isPending}
                      >
                        Approve
                      </button>
                      <button
                        type="button"
                        className="px-3 py-1.5 rounded-xl bg-rose-500/80 text-slate-950 text-xs font-semibold hover:bg-rose-400 transition"
                        onClick={() => reject.mutate(request.request_id)}
                        disabled={reject.isPending}
                      >
                        Reject
                      </button>
                    </div>
                  ) : (
                    <span className="text-xs text-slate-600">Manager permissions required</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
