// Software-only simulation / demo - no real systems will be contacted or modified.
import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import axios from 'axios';
import SimulationTerminal from '../../frontend/src/components/SimulationTerminal.jsx';

jest.mock('axios');

test('sends command and displays output', async () => {
  axios.post.mockResolvedValueOnce({ data: { output: 'directory listing', alerts_triggered: [] } });
  render(<SimulationTerminal sessionId="test-session" />);

  const input = screen.getByPlaceholderText(/enter command/i);
  fireEvent.change(input, { target: { value: 'ls' } });
  fireEvent.submit(input.closest('form'));

  await waitFor(() => expect(screen.getByText('directory listing')).toBeInTheDocument());
  expect(axios.post).toHaveBeenCalledWith('/api/v1/simulation/terminal', {
    session_id: 'test-session',
    command: 'ls',
  });
});
