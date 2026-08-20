import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import type { ReactElement } from 'react';
import Orchestrator from './pages/Orchestrator';
import SOCDashboard from './pages/SOCDashboard';
import Metrics from './pages/Metrics';
import Login from './pages/Login';
import { isAuthenticated } from './services/api';

/** Route guard — everything except /login requires a JWT from the API. */
const RequireAuth = ({ children }: { children: ReactElement }) =>
  isAuthenticated() ? children : <Navigate to="/login" replace />;

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<RequireAuth><SOCDashboard /></RequireAuth>} />
        <Route path="/orchestrator" element={<RequireAuth><Orchestrator /></RequireAuth>} />
        <Route path="/metrics" element={<RequireAuth><Metrics /></RequireAuth>} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
