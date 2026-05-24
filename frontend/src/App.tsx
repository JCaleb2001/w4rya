import {
  BrowserRouter,
  Routes,
  Route,
  Outlet,
  Navigate,
} from "react-router-dom";
import { Suspense } from "react";
import { useHotkeys } from 'react-hotkeys-hook';

import "./App.css";
import { Header } from "./components/Header";
import { Home } from "./pages/Home";
import { FlowList } from "./components/FlowList";
import { FlowView } from "./pages/FlowView";
import { DiffView } from "./pages/DiffView";
import { Corrie } from "./components/Corrie";
import { Login } from "./pages/Login";
import { useGetMeQuery } from "./api";

function RequireAuth({ children }: { children: JSX.Element }) {
  const { data, isLoading, isError } = useGetMeQuery();
  if (isLoading) {
    return (
      <div className="min-h-screen bg-hax-bg text-hax-muted flex items-center justify-center font-mono text-xs uppercase tracking-[0.3em]">
        <span className="text-hax-accent-bright">$</span>&nbsp;establishing session<span className="hax-cursor"></span>
      </div>
    );
  }
  if (isError || !data?.user) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

function App() {
  useHotkeys('esc', () => (document.activeElement as HTMLElement).blur(), {enableOnFormTags: true});
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/"
          element={
            <RequireAuth>
              <Layout />
            </RequireAuth>
          }
        >
          <Route index element={<Home />} />
          <Route
            path="flow/:id"
            element={
              <Suspense>
                <FlowView />
              </Suspense>
            }
          />
          <Route
            path="diff/:id"
            element={
              <Suspense>
                <DiffView />
              </Suspense>
            }
          />
          <Route
            path="corrie/"
            element={
              <Suspense>
                <Corrie />
              </Suspense>
            }
          />
        </Route>
        <Route path="*" element={<PageNotFound />} />
      </Routes>
    </BrowserRouter>
  );
}

function Layout() {
  return (
    <div className="grid-container">
      <header className="header-area">
        <div className="header">
          <Header></Header>
        </div>
      </header>
      <aside className="flow-list-area">
        <Suspense>
          <FlowList></FlowList>
        </Suspense>
      </aside>
      <main className="flow-details-area">
        <Outlet />
      </main>
      <footer className="footer-area"></footer>
    </div>
  );
}


function PageNotFound() {
  return (
    <div className="min-h-screen bg-hax-bg text-hax-text font-mono flex flex-col items-center justify-center gap-2">
      <div className="text-[10px] uppercase tracking-[0.4em] text-hax-accent-bright">▎404</div>
      <h2 className="text-3xl tracking-widest">page not found</h2>
    </div>
  );
}

export default App;
