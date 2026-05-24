import { format, parse } from "date-fns";
import { Suspense, useState } from "react";
import { useHotkeys } from 'react-hotkeys-hook';
import {
  Link,
  useParams,
  useSearchParams,
  useNavigate,
} from "react-router-dom";
import ReactDiffViewer from "react-diff-viewer";

import {
  END_FILTER_KEY,
  SERVICE_FILTER_KEY,
  START_FILTER_KEY,
  TEXT_FILTER_KEY,
  FIRST_DIFF_KEY,
  SECOND_DIFF_KEY,
  SERVICE_REFETCH_INTERVAL_MS,
  REPR_ID_KEY,
} from "../const";
import {
  useGetFlowQuery,
  useGetServicesQuery,
  useGetMeQuery,
  useLogoutMutation,
  hasRole,
} from "../api";
import { getTickStuff } from "../tick";

function TextSearch() {
  const FILTER_KEY = TEXT_FILTER_KEY;
  let [searchParams, setSearchParams] = useSearchParams();
  useHotkeys('s', (e) => {
    let el = document.getElementById('search') as HTMLInputElement;
    el?.focus();
    el?.select();
    e.preventDefault()
  });
  return (
    <div>
      <input
        type="text"
        placeholder="regex"
        id="search"
        value={searchParams.get(FILTER_KEY) || ""}
        onChange={(event) => {
          let textFilter = event.target.value;
          if (textFilter) {
            searchParams.set(FILTER_KEY, textFilter);
          } else {
            searchParams.delete(FILTER_KEY);
          }
          setSearchParams(searchParams);
        }}
      ></input>
    </div>
  );
}


function StartDateSelection() {
  let { startTickParam, setTimeParam } = getTickStuff();
  return (
    <div>
      <input
        className="w-20"
        id="startdateselection"
        type="number"
        placeholder="from"
        value={startTickParam}
        onChange={(event) => {
          setTimeParam(event.target.value == "" ? null : parseInt(event.target.value), START_FILTER_KEY);
        }}
      ></input>
    </div>
  );
}

function EndDateSelection() {
  let { endTickParam, setTimeParam } = getTickStuff();
  return (
    <div>
      <input
        className="w-20"
        id="enddateselection"
        type="number"
        placeholder="to"
        value={endTickParam}
        onChange={(event) => {
          setTimeParam(event.target.value == "" ? null : parseInt(event.target.value), END_FILTER_KEY);
        }}
      ></input>
    </div>
  );
}

function FirstDiff() {
  let params = useParams();
  let [searchParams, setSearchParams] = useSearchParams();
  const [firstFlow, setFirstFlow] = useState<string>(
    searchParams.get(FIRST_DIFF_KEY) ?? ""
  );

  function setFirstDiffFlow() {
    let textFilter = params.id;
    let reprId = searchParams.get(REPR_ID_KEY);
    let reprIdSlug = reprId ? `${textFilter}:${reprId}` : `${textFilter}`
    if (textFilter) {
      searchParams.set(FIRST_DIFF_KEY, reprIdSlug);
      setFirstFlow(reprIdSlug);
    } else {
      searchParams.delete(FIRST_DIFF_KEY);
      setFirstFlow("");
    }
    setSearchParams(searchParams);
  }

  useHotkeys("f", () => {
    setFirstDiffFlow();
  });

  return (
    <input
      type="text"
      className="md:w-72"
      placeholder="First Diff ID"
      readOnly
      value={firstFlow}
      onClick={(event) => setFirstDiffFlow()}
      onContextMenu={(event) => {
        searchParams.delete(FIRST_DIFF_KEY);
        setFirstFlow("");
        setSearchParams(searchParams);
        event.preventDefault();
      }}
    ></input>
  );
}

function SecondDiff() {
  let params = useParams();
  let [searchParams, setSearchParams] = useSearchParams();
  const [secondFlow, setSecondFlow] = useState<string>(
    searchParams.get(SECOND_DIFF_KEY) ?? ""
  );

  function setSecondDiffFlow() {
    let textFilter = params.id;
    let reprId = searchParams.get(REPR_ID_KEY);
    let reprIdSlug = reprId ? `${textFilter}:${reprId}` : `${textFilter}`
    if (textFilter) {
      searchParams.set(SECOND_DIFF_KEY, reprIdSlug);
      setSecondFlow(reprIdSlug);
    } else {
      searchParams.delete(SECOND_DIFF_KEY);
      setSecondFlow("");
    }
    setSearchParams(searchParams);
  }

  useHotkeys("e", () => {
    setSecondDiffFlow();
  });

  return (
    <input
      type="text"
      className="md:w-72"
      placeholder="Second Flow ID"
      readOnly
      value={secondFlow}
      onClick={(event) => setSecondDiffFlow()}
      onContextMenu={(event) => {
        searchParams.delete(SECOND_DIFF_KEY);
        setSecondFlow("");
        setSearchParams(searchParams);
        event.preventDefault();
      }}
    ></input>
  );
}

function Diff() {
  let params = useParams();

  let [searchParams] = useSearchParams();

  let navigate = useNavigate();

  function navigateToDiff() {
    navigate(`/diff/${params.id ?? ""}?${searchParams}`, { replace: true });
  }

  useHotkeys("d", () => {
    navigateToDiff();
  });

  return (
    <button
      className="hax-btn hax-btn-primary"
      onClick={() => {
        navigateToDiff()
      }}
    >
      Diff
    </button>
  );
}

function UserMenu() {
  const { data: me } = useGetMeQuery();
  const [logout, { isLoading }] = useLogoutMutation();
  if (!me?.user) return null;
  const roleColor =
    me.role === "admin"
      ? "text-hax-danger"
      : me.role === "operator"
      ? "text-hax-warning"
      : "text-hax-muted";
  return (
    <div className="flex items-center gap-2 font-mono">
      <div className="text-xs uppercase tracking-[0.15em]">
        <span className="text-hax-muted">user</span>{" "}
        <span className="text-hax-accent-bright">{me.user}</span>
        <span className={`ml-1 ${roleColor}`} title={`role: ${me.role}`}>
          [{me.role ?? "?"}]
        </span>
      </div>
      <button
        className="hax-btn"
        disabled={isLoading}
        onClick={() => logout()}
        title="Logout"
      >
        {isLoading ? "…" : "logout"}
      </button>
    </div>
  );
}

export function Header() {
  let { currentTick, setToLastnTicks, setTimeParam } = getTickStuff();
  let [searchParams] = useSearchParams();

  let navigate = useNavigate();

  useHotkeys('g', () => navigate(`/corrie?${searchParams}`, { replace: true }))
  useHotkeys('a', () => setToLastnTicks(5));
  useHotkeys('c', () => {
    (document.getElementById("startdateselection") as HTMLInputElement).value = "";
    (document.getElementById("enddateselection") as HTMLInputElement).value = "";
    setTimeParam(null, START_FILTER_KEY);
    setTimeParam(null, END_FILTER_KEY);
  });

  return (
    <>
      <Link to={`/?${searchParams}`}>
        <div className="header-icon">
          <img src="/logo.png" alt="w4rya" className="h-7 w-7" />
          <span className="brand text-base">w4rya</span>
        </div>
      </Link>
      <div>
        <TextSearch></TextSearch>
      </div>
      <div>
        <StartDateSelection></StartDateSelection>
      </div>
      <div>
        <EndDateSelection></EndDateSelection>
      </div>
      <div>
        <button
          className="hax-btn hax-btn-primary"
          onClick={() => setToLastnTicks(5)}
        >
          Last 5 ticks
        </button>
      </div>
      <Link to={`/corrie?${searchParams}`}>
        <div className="hax-btn">
          Graph view
        </div>
      </Link>
      <Link to="/attacks">
        <div className="hax-btn">
          Attacks
        </div>
      </Link>
      <Link to="/warroom">
        <div className="hax-btn" title="fullscreen TV mode">
          War room
        </div>
      </Link>
      <Link to="/config">
        <div className="hax-btn">
          Config
        </div>
      </Link>
      <Link to="/rules">
        <div className="hax-btn">
          Rules
        </div>
      </Link>
      {hasRole(useGetMeQuery().data?.role, "admin") && (
        <Link to="/audit">
          <div className="hax-btn">
            Audit
          </div>
        </Link>
      )}
      <div className="ml-auto mr-4" style={{ display: "flex" }}>
        <div className="mr-4">
          <FirstDiff />
        </div>
        <div className="mr-4">
          <SecondDiff />
        </div>
        <div className="mr-6">
          <Suspense>
            <Diff />
          </Suspense>
        </div>
        <div
          className="ml-auto text-xs uppercase tracking-[0.2em] font-mono"
          style={{
            display: "flex",
            justifyContent: "center",
            alignContent: "center",
            flexDirection: "column",
          }}
        >
          <span className="text-hax-muted">tick</span>
          <span className="text-hax-accent-bright hax-glow text-lg leading-tight">
            {currentTick}
          </span>
        </div>
        <div className="ml-4 mr-2 self-center">
          <UserMenu />
        </div>
      </div>
    </>
  );
}
