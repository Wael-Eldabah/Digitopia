// Software-only simulation / demo - no real systems will be contacted or modified.
import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import axios from 'axios';
import SettingsPanel from '../../frontend/src/components/SettingsPanel.jsx';

jest.mock('axios');

const wrapper = ({ children }) => {
  const client = new QueryClient();
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
};

test('lists users and pending requests', async () => {
  axios.get
    .mockResolvedValueOnce({ data: [{ id: 'u1', email: 'user@eyeguard.com', role: 'SOC_ANALYST', status: 'active' }] })
    .mockResolvedValueOnce({ data: [{ request_id: 'r1', email: 'pending@eyeguard.com', role: 'INCIDENT_RESPONDER' }] });

  render(<SettingsPanel />, { wrapper });

  await waitFor(() => expect(screen.getByText('user@eyeguard.com')).toBeInTheDocument());
  expect(screen.getByText('pending@eyeguard.com')).toBeInTheDocument();

  axios.post.mockResolvedValueOnce({ data: {} });
  fireEvent.click(screen.getByText(/Approve/i));
  await waitFor(() => expect(axios.post).toHaveBeenCalled());
});
