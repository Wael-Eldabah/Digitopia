// Software-only simulation / demo - no real systems will be contacted or modified.
import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Sidebar from '../../frontend/src/components/Sidebar.jsx';

test('renders navigation links', () => {
  render(
    <MemoryRouter>
      <Sidebar />
    </MemoryRouter>,
  );
  expect(screen.getByText(/Dashboard/i)).toBeInTheDocument();
  expect(screen.getByText(/Alerts & Incidents/i)).toBeInTheDocument();
  expect(screen.getByText(/Simulation/i)).toBeInTheDocument();
});

