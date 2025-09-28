// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useContext, useEffect, useMemo, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import axios from 'axios';
import { AuthContext } from '../App.jsx';
import { resolveAssetUrl } from '../utils/assets.js';

const fetchSettingsData = async () => {
  const usersResponse = await axios.get('/api/v1/settings/users');

  let pending = [];
  try {
    const pendingResponse = await axios.get('/api/v1/settings/users/pending');
    pending = pendingResponse.data;
  } catch (pendingError) {
    const status = pendingError?.response?.status;
    if (status !== 403) {
      throw pendingError;
    }
  }

  const users = Array.isArray(usersResponse.data)
    ? usersResponse.data.map((entry) => ({
        ...entry,
        profile_image_url: resolveAssetUrl(entry.profile_image_url),
      }))
    : [];

  return { users, pending };
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

const avatarAccents = ['#1e293b', '#1d4ed8', '#0284c7', '#0f766e', '#9333ea'];
const pickAccentColor = () => avatarAccents[Math.floor(Math.random() * avatarAccents.length)];
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/i;

export default function SettingsPanel() {
  const queryClient = useQueryClient();
  const { user, updateUser, managerPending, setManagerPending, refreshProfile } = useContext(AuthContext);
  const { data, isLoading } = useQuery({ queryKey: ['settings-users'], queryFn: fetchSettingsData });

  const [profileForm, setProfileForm] = useState({
    displayName: user?.display_name || '',
    email: user?.email || '',
    role: user?.role || 'SOC_ANALYST',
    alertEmail: user?.alert_email || '',
  });
  const [teamEmails, setTeamEmails] = useState(user?.team_alert_emails || []);
  const [teamEmailDraft, setTeamEmailDraft] = useState('');
  const [teamEmailError, setTeamEmailError] = useState('');
  const [alertEmailError, setAlertEmailError] = useState('');
  const [notifications, setNotifications] = useState({
    criticalEmail: user?.notifications?.critical_email ?? true,
    weeklyDigest: user?.notifications?.weekly_digest ?? true,
    push: user?.notifications?.push ?? false,
  });
  const [apiKey, setApiKey] = useState('eyeg-4c1d-7b28-training');
  const [feedback, setFeedback] = useState('');
  const [error, setError] = useState('');
  const [uploadPreview, setUploadPreview] = useState(() => resolveAssetUrl(user?.profile_image_url));
  const [uploadError, setUploadError] = useState('');
  const fileInputRef = useRef(null);
  const uploadObjectUrlRef = useRef(null);
  const [avatarAccent, setAvatarAccent] = useState(() => (resolveAssetUrl(user?.profile_image_url) ? '#1e293b' : pickAccentColor()));
  const [integrationForm, setIntegrationForm] = useState({ vt_api_key: '', otx_api_key: '', abuse_api_key: '' });
  const [integrationFeedback, setIntegrationFeedback] = useState({ message: '', error: '' });
  const isManager = user?.role === 'MANAGER';
  const integrationQuery = useQuery({
    queryKey: ['integration-keys'],
    queryFn: async () => {
      const { data: keys } = await axios.get('/api/v1/settings/profile/integrations');
      return keys;
    },
    enabled: isManager,
  });

  const integrationStatus = useMemo(() => {
    const source = integrationQuery.data || {};
    return [
      { key: 'vt_api_key', label: 'VirusTotal', present: Boolean(source.vt_api_key) },
      { key: 'otx_api_key', label: 'AlienVault OTX', present: Boolean(source.otx_api_key) },
      { key: 'abuse_api_key', label: 'AbuseIPDB', present: Boolean(source.abuse_api_key) },
    ];
  }, [integrationQuery.data]);

  const missingIntegrations = useMemo(() => integrationStatus.filter((item) => !item.present), [integrationStatus]);

  useEffect(() => {
    if (!user) {
      return;
    }
    const resolvedImage = resolveAssetUrl(user.profile_image_url);
    setProfileForm({
      displayName: user.display_name || '',
      email: user.email,
      role: user.role,
      alertEmail: user.alert_email || '',
    });
    setTeamEmails(user.team_alert_emails || []);
    setTeamEmailDraft('');
    setTeamEmailError('');
    setAlertEmailError('');
    setNotifications({
      criticalEmail: user.notifications?.critical_email ?? true,
      weeklyDigest: user.notifications?.weekly_digest ?? true,
      push: user.notifications?.push ?? false,
    });
    if (uploadObjectUrlRef.current) {
      URL.revokeObjectURL(uploadObjectUrlRef.current);
      uploadObjectUrlRef.current = null;
    }
    setUploadPreview(resolvedImage || '');
    if (resolvedImage) {
      setAvatarAccent('#1e293b');
    } else {
      setAvatarAccent(pickAccentColor());
    }
  }, [user]);

  useEffect(() => {
    if (!isManager) {
      setIntegrationForm({ vt_api_key: '', otx_api_key: '', abuse_api_key: '' });
      setIntegrationFeedback({ message: '', error: '' });
      return;
    }
    if (integrationQuery.data) {
      setIntegrationForm({
        vt_api_key: integrationQuery.data.vt_api_key || '',
        otx_api_key: integrationQuery.data.otx_api_key || '',
        abuse_api_key: integrationQuery.data.abuse_api_key || '',
      });
    }
  }, [isManager, integrationQuery.data]);

  useEffect(() => {
    if (user?.role === 'MANAGER' && data?.pending) {
      setManagerPending(data.pending.length);
    }
  }, [data?.pending, user?.role, setManagerPending]);

  useEffect(() => () => {
    if (uploadObjectUrlRef.current) {
      URL.revokeObjectURL(uploadObjectUrlRef.current);
      uploadObjectUrlRef.current = null;
    }
  }, []);

  const profileMutation = useMutation({
    mutationFn: (payload) => axios.patch('/api/v1/settings/profile', payload),
    onMutate: () => {
      setFeedback('');
      setError('');
      setAlertEmailError('');
      setTeamEmailError('');
    },
    onSuccess: ({ data: updated }) => {
      updateUser(updated);
      setTeamEmails(updated.team_alert_emails || []);
      setProfileForm((prev) => ({
        ...prev,
        displayName: updated.display_name || '',
        email: updated.email,
        role: updated.role || prev.role,
        alertEmail: updated.alert_email || '',
      }));
      setAlertEmailError('');
      setTeamEmailError('');
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
      const resolved = resolveAssetUrl(updated.profile_image_url);
      updateUser(updated);
      if (uploadObjectUrlRef.current) {
        URL.revokeObjectURL(uploadObjectUrlRef.current);
        uploadObjectUrlRef.current = null;
      }
      setUploadPreview(resolved || '');
      if (resolved) {
        setAvatarAccent('#1e293b');
      } else {
        setAvatarAccent(pickAccentColor());
      }
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
      if (uploadObjectUrlRef.current) {
        URL.revokeObjectURL(uploadObjectUrlRef.current);
        uploadObjectUrlRef.current = null;
      }
      const fallback = resolveAssetUrl(user?.profile_image_url);
      setUploadPreview(fallback || '');
      if (fallback) {
        setAvatarAccent('#1e293b');
      } else {
        setAvatarAccent(pickAccentColor());
      }
    },
    onSuccess: ({ data: response }) => {
      const resolved = resolveAssetUrl(response.profile_image_url);
      if (uploadObjectUrlRef.current) {
        URL.revokeObjectURL(uploadObjectUrlRef.current);
        uploadObjectUrlRef.current = null;
      }
      setUploadPreview(resolved || '');
      if (resolved) {
        setAvatarAccent('#1e293b');
      } else {
        setAvatarAccent(pickAccentColor());
      }
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

  const integrationMutation = useMutation({
    mutationFn: (payload) => axios.patch('/api/v1/settings/profile/integrations', payload),
    onMutate: () => {
      setIntegrationFeedback({ message: '', error: '' });
    },
    onSuccess: ({ data: updated }) => {
      setIntegrationForm({
        vt_api_key: updated.vt_api_key || '',
        otx_api_key: updated.otx_api_key || '',
        abuse_api_key: updated.abuse_api_key || '',
      });
      queryClient.setQueryData(['integration-keys'], updated);
      setIntegrationFeedback({ message: 'Threat intelligence API keys updated.', error: '' });
    },
    onError: (err) => {
      const message = err?.response?.data?.detail?.message || 'Unable to update integration keys.';
      setIntegrationFeedback({ message: '', error: message });
    },
  });

  const handleIntegrationChange = (event) => {
    const { name, value } = event.target;
    setIntegrationForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleSaveIntegrations = () => {
    if (!isManager) {
      return;
    }
    integrationMutation.mutate({
      vt_api_key: integrationForm.vt_api_key || null,
      otx_api_key: integrationForm.otx_api_key || null,
      abuse_api_key: integrationForm.abuse_api_key || null,
    });
  };

  const handleSaveProfile = () => {
    setFeedback('');
    setError('');
    if (profileForm.alertEmail && !emailPattern.test(profileForm.alertEmail.trim())) {
      setAlertEmailError('Enter a valid alert email address.');
      return;
    }
    setAlertEmailError('');
    const sanitizedTeamEmails = teamEmails.map((email) => email.trim()).filter(Boolean);
    if (sanitizedTeamEmails.some((entry) => !emailPattern.test(entry))) {
      setTeamEmailError('One or more team alert emails are invalid.');
      return;
    }
    setTeamEmailError('');
    profileMutation.mutate({
      display_name: profileForm.displayName,
      email: profileForm.email,
      alert_email: profileForm.alertEmail.trim() || null,
      team_alert_emails: isManager ? sanitizedTeamEmails : undefined,
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

  const handleTeamEmailAdd = () => {
    if (!teamEmailDraft.trim()) {
      return;
    }
    const candidate = teamEmailDraft.trim();
    if (!emailPattern.test(candidate)) {
      setTeamEmailError('Enter a valid email address.');
      return;
    }
    if (teamEmails.some((email) => email.toLowerCase() === candidate.toLowerCase())) {
      setTeamEmailError('Email already added.');
      return;
    }
    setTeamEmails((prev) => [...prev, candidate]);
    setTeamEmailDraft('');
    setTeamEmailError('');
  };

  const handleTeamEmailRemove = (email) => {
    setTeamEmails((prev) => prev.filter((entry) => entry !== email));
    setTeamEmailError('');
  };

  const handleTeamEmailKeyDown = (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      handleTeamEmailAdd();
    }
  };

  const handleFileSelect = (event) => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }
    setUploadError('');
    if (uploadObjectUrlRef.current) {
      URL.revokeObjectURL(uploadObjectUrlRef.current);
      uploadObjectUrlRef.current = null;
    }
    const previewUrl = URL.createObjectURL(file);
    uploadObjectUrlRef.current = previewUrl;
    setUploadPreview(previewUrl);
    setAvatarAccent('#1e293b');
    uploadMutation.mutate(file);
  };

  const handleUploadClick = () => {
    fileInputRef.current?.click();
  };

  const profileInitials = initialsFromName(profileForm.displayName, initialsFromName(user?.email || 'Analyst', 'EG'));

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
                <div
                  className="h-14 w-14 rounded-2xl flex items-center justify-center text-lg font-semibold text-slate-950 shadow-inner"
                  style={{ backgroundColor: avatarAccent }}
                >
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
                onClick={() => {
                  if (!uploadPreview) {
                    setAvatarAccent(pickAccentColor());
                  }
                  avatarMutation.mutate();
                }}
                className="px-3 py-1.5 rounded-xl bg-sky-500/80 text-slate-950 text-xs font-semibold hover:bg-sky-400 transition disabled:opacity-60"
                disabled={avatarMutation.isPending}
              >
                {avatarMutation.isPending ? 'Generating...' : 'Change Avatar'}
              </button>
            </div>
          </div>
          <div className="mt-6 grid md:grid-cols-2 gap-5 text-sm">
            <div className="space-y-2">
              <label className=" text-xs uppercase tracking-wide text-slate-500 mr-2">Full Name</label>
              <input
                value={profileForm.displayName}
                onChange={(event) => setProfileForm((prev) => ({ ...prev, displayName: event.target.value }))}
                className="bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wide text-slate-500 mr-2">Email Address</label>
              <input
                value={profileForm.email}
                onChange={(event) => setProfileForm((prev) => ({ ...prev, email: event.target.value }))}
                className="bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wide text-slate-500 mr-2">Alert Email</label>
              <input
                type="email"
                value={profileForm.alertEmail}
                onChange={(event) => setProfileForm((prev) => ({ ...prev, alertEmail: event.target.value }))}
                className="bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
                placeholder="alerts@eyeguard.com"
              />
              <p className="text-[11px] text-slate-500">High severity alerts will be routed to this address.</p>
              {alertEmailError && <p className="text-xs text-rose-400">{alertEmailError}</p>}
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wide text-slate-500 mr-2">Role</label>
              <input
                value={profileForm.role.replace('_', ' ')}
                readOnly
                className="bg-slate-900/40 border border-slate-800 rounded-xl px-3 py-2 text-slate-400 uppercase tracking-wide"
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wide text-slate-500 mr-2">Account State</label>
              <input
                value={user?.status || 'pending'}
                readOnly
                className="bg-slate-900/40 border border-slate-800 rounded-xl px-3 py-2 text-slate-400 uppercase tracking-wide"
              />
            </div>
          </div>
          {isManager && (
            <div className="mt-6 space-y-3">
              <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
                <h4 className="text-sm font-semibold text-slate-200">Team Alert Emails</h4>
                <span className="text-[11px] uppercase tracking-wide text-slate-500">Forward high priority alerts</span>
              </div>
              <p className="text-xs text-slate-500">Managers can distribute alert notifications to additional teammates.</p>
              <div className="flex flex-wrap gap-2">
                {teamEmails.length === 0 ? (
                  <span className="text-xs text-slate-600">No team emails configured.</span>
                ) : (
                  teamEmails.map((email) => (
                    <span key={email} className="inline-flex items-center gap-2 rounded-full bg-slate-800/70 px-3 py-1 text-xs text-slate-200">
                      {email}
                      <button
                        type="button"
                        className="text-slate-400 hover:text-rose-400 transition"
                        onClick={() => handleTeamEmailRemove(email)}
                        aria-label={`Remove ${email}`}
                      >
                        &times;
                      </button>
                    </span>
                  ))
                )}
              </div>
              {isManager && teamEmails.length > 0 && !notifications.criticalEmail && (
                <p className="text-xs text-amber-300">Critical alert emails are required to notify this list. They will be re-enabled when the profile is saved.</p>
              )}
              <div className="flex flex-col gap-2 sm:flex-row">
                <input
                  type="email"
                  value={teamEmailDraft}
                  onChange={(event) => setTeamEmailDraft(event.target.value)}
                  onKeyDown={handleTeamEmailKeyDown}
                  placeholder="team-alerts@eyeguard.com"
                  className="bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200 focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/30 flex-1"
                />
                <button
                  type="button"
                  onClick={handleTeamEmailAdd}
                  className="px-3 py-2 rounded-xl bg-emerald-500/80 text-slate-950 text-xs font-semibold hover:bg-emerald-400 transition"
                >
                  Add Email
                </button>
              </div>
              {teamEmailError && <p className="text-xs text-rose-400">{teamEmailError}</p>}
            </div>
          )}
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

        {isManager && (
          <section className="bg-[#101b30] border border-slate-800/70 rounded-3xl p-8 space-y-6 shadow-[0_25px_60px_rgba(8,17,32,0.55)]">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-slate-100">Threat Intel API Keys</h3>
                <p className="text-xs uppercase tracking-wider text-slate-500">Used for IP reputation lookups</p>
              </div>
              <button
                type="button"
                onClick={regenerateKey}
                className="px-3 py-2 rounded-xl bg-emerald-500/80 text-slate-950 text-xs font-semibold hover:bg-emerald-400 transition"
              >
                Generate Sandbox Key
              </button>
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              {integrationStatus.map((item) => (
                <div
                  key={item.key}
                  className={`rounded-2xl border px-3 py-3 text-xs ${item.present ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200' : 'border-rose-500/40 bg-rose-500/10 text-rose-200'}`}
                >
                  <p className="text-sm font-semibold text-slate-100">{item.label}</p>
                  <p>{item.present ? 'Connected' : 'Missing'}</p>
                </div>
              ))}
            </div>
            {missingIntegrations.length > 0 && (
              <p className="text-xs text-amber-300">Missing keys: {missingIntegrations.map((item) => item.label).join(', ')}. Lookups will use mock telemetry until these keys are provided.</p>
            )}
            <div className="grid gap-4 md:grid-cols-3">
              <div className="space-y-2">
                <label className="text-xs uppercase tracking-wide text-slate-500">VirusTotal API Key</label>
                <input
                  name="vt_api_key"
                  value={integrationForm.vt_api_key}
                  onChange={handleIntegrationChange}
                  className="bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
                  placeholder="Optional"
                />
              </div>
              <div className="space-y-2">
                <label className="text-xs uppercase tracking-wide text-slate-500">AlienVault OTX Key</label>
                <input
                  name="otx_api_key"
                  value={integrationForm.otx_api_key}
                  onChange={handleIntegrationChange}
                  className="bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
                  placeholder="Optional"
                />
              </div>
              <div className="space-y-2">
                <label className="text-xs uppercase tracking-wide text-slate-500">AbuseIPDB Key</label>
                <input
                  name="abuse_api_key"
                  value={integrationForm.abuse_api_key}
                  onChange={handleIntegrationChange}
                  className="bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
                  placeholder="Optional"
                />
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={handleSaveIntegrations}
                className="px-4 py-2 rounded-xl bg-sky-500/80 text-slate-950 text-xs font-semibold hover:bg-sky-400 transition disabled:opacity-60"
                disabled={integrationMutation.isPending || integrationQuery.isFetching}
              >
                {integrationMutation.isPending ? 'Saving...' : 'Save API Keys'}
              </button>
              <div className="text-xs text-slate-500">Leave blank to fall back to built-in mock data.</div>
            </div>
            {integrationFeedback.message && (
              <p className="text-xs text-emerald-300">{integrationFeedback.message}</p>
            )}
            {integrationFeedback.error && (
              <p className="text-xs text-rose-400">{integrationFeedback.error}</p>
            )}
            <div className="bg-slate-900/70 border border-slate-800 rounded-2xl px-4 py-3 font-mono text-xs text-emerald-300 flex items-center justify-between">
              <span>{apiKey}</span>
              <span className="text-[10px] text-slate-500 uppercase tracking-wide">Sandbox Token</span>
            </div>
          </section>
        )}
      </div>

      {isManager && (
        <div className="space-y-6">
          <section className="bg-[#101b30] border border-slate-800/70 rounded-3xl p-6 shadow-[0_25px_60px_rgba(8,17,32,0.55)]">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-slate-100">Active Team</h3>
              <span className="text-xs text-emerald-300">Pending: {managerPending}</span>
            </div>
            <ul className="space-y-4">
              {data.users.map((entry) => (
                <li key={entry.id} className="bg-slate-900/60 border border-slate-800/70 rounded-2xl px-4 py-3 space-y-2">
                  <div className="flex items-center justify-between gap-4">
                    <div className="space-y-1">
                      <p className="text-sm font-semibold text-slate-100">{entry.display_name || entry.email}</p>
                      <p className="text-[11px] uppercase tracking-wide text-slate-500">{entry.role.replace('_', ' ')}</p>
                      <p className="text-xs text-slate-400">{entry.email}</p>
                      {entry.alert_email && (
                        <p className="text-xs text-slate-500">Alert Email: <span className="text-slate-300">{entry.alert_email}</span></p>
                      )}
                      {entry.team_alert_emails?.length ? (
                        <p className="text-xs text-slate-500">Team: <span className="text-slate-300">{entry.team_alert_emails.join(', ')}</span></p>
                      ) : null}
                    </div>
                    <div className="flex flex-col items-end gap-2">
                      {entry.profile_image_url ? (
                        <img src={entry.profile_image_url} alt={entry.display_name || entry.email} className="h-9 w-9 rounded-full object-cover border border-slate-700" />
                      ) : (
                        <div className="h-9 w-9 rounded-full bg-slate-800/70 flex items-center justify-center text-[11px] text-slate-300">
                          {initialsFromName(entry.display_name || entry.email, 'EG')}
                        </div>
                      )}
                      <span className={`text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-full ${entry.status === 'active' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-800/70 text-slate-400'}`}>{entry.status}</span>
                    </div>
                  </div>
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
                  </div>
                </div>
              ))}
            </div>
          </section>
        </div>
      )}
    </div>
  );
}

