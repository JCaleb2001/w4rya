import { useSearchParams, Link, useParams } from "react-router-dom";
import { useState } from "react";
import { Buffer } from "buffer";

import { FullFlow } from "../types";

import ReactDiffViewer from "react-diff-viewer";
import { RadioGroup } from "../components/RadioGroup";

import { hexy } from "hexy";

import { FIRST_DIFF_KEY, SECOND_DIFF_KEY } from "../const";
import { useGetFlowQuery } from "../api";

function Flow(flow1: string, flow2: string) {
  return (
    <div>
      <ReactDiffViewer
        oldValue={flow1}
        newValue={flow2}
        splitView={true}
        showDiffOnly={false}
        useDarkTheme={true}
        hideLineNumbers={true}
        styles={{
          line: {
            wordBreak: "break-word",
          },
          variables: {
            dark: {
              diffViewerBackground: '#13131c',
              diffViewerColor: '#e4e4ed',
              addedBackground: 'rgba(34, 197, 94, 0.12)',
              addedColor: '#86efac',
              removedBackground: 'rgba(239, 68, 68, 0.12)',
              removedColor: '#fca5a5',
              wordAddedBackground: 'rgba(34, 197, 94, 0.3)',
              wordRemovedBackground: 'rgba(239, 68, 68, 0.3)',
              addedGutterBackground: 'rgba(34, 197, 94, 0.2)',
              removedGutterBackground: 'rgba(239, 68, 68, 0.2)',
              gutterBackground: '#1c1c28',
              gutterBackgroundDark: '#13131c',
              highlightBackground: 'rgba(168, 85, 247, 0.15)',
              highlightGutterBackground: 'rgba(168, 85, 247, 0.25)',
              codeFoldGutterBackground: '#1c1c28',
              codeFoldBackground: '#1c1c28',
              emptyLineBackground: '#0a0a0f',
              gutterColor: '#5a5a72',
              addedGutterColor: '#22c55e',
              removedGutterColor: '#ef4444',
              codeFoldContentColor: '#8888a0',
              diffViewerTitleBackground: '#1c1c28',
              diffViewerTitleColor: '#e4e4ed',
              diffViewerTitleBorderColor: '#2a2a3a',
            },
          },
        }}
      />
      <hr
        style={{
          height: "1px",
          color: "inherit",
          borderTopWidth: "5px",
        }}
      />
    </div>
  );
}

function isASCII(str: string) {
  return /^[\x00-\x7F]*$/.test(str);
}

const displayOptions = ["Plain", "Hex"];

// Derives the display mode for two given flows
const deriveDisplayMode = (
  firstFlow: FullFlow,
  secondFlow: FullFlow
): typeof displayOptions[number] => {
  if (firstFlow && secondFlow) {
    for (
      let i = 0;
      i < Math.min(firstFlow.flow.length, secondFlow.flow.length);
      i++
    ) {
      if (
        !isASCII(firstFlow.flow[0].flow[i].data) ||
        !isASCII(secondFlow.flow[0].flow[i].data)
      ) {
        return displayOptions[1];
      }
    }
  }

  return displayOptions[0];
};

export function DiffView() {
  let [searchParams] = useSearchParams();
  const firstFlowParam = searchParams.get(FIRST_DIFF_KEY);
  const firstFlowId = firstFlowParam?.split(":")[0];
  const firstFlowRepr = parseInt(firstFlowParam?.split(":")[1] ?? "0");
  const secondFlowParam = searchParams.get(SECOND_DIFF_KEY);
  const secondFlowId = secondFlowParam?.split(":")[0];
  const secondFlowRepr = parseInt(secondFlowParam?.split(":")[1] ?? "0");

  let { data: firstFlow, isLoading: firstFlowLoading, isError: firstFlowError } = useGetFlowQuery(
    firstFlowId!,
    {
      skip: firstFlowId === null,
    }
  );
  let { data: secondFlow, isLoading: secondFlowLoading, isError: secondFlowError } = useGetFlowQuery(
    secondFlowId!,
    {
      skip: secondFlowId === null,
    }
  );

  const [displayOption, setDisplayOption] = useState(
    deriveDisplayMode(firstFlow!, secondFlow!)
  );

  if (firstFlowError || secondFlowError) {
    return <div>Invalid flow id</div>;
  }

  if (firstFlowLoading || secondFlowLoading) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      <div className="sticky shadow-md bg-hax-surface overflow-auto py-1 border-y border-hax-border flex items-center px-2">
        <RadioGroup
          options={displayOptions}
          value={displayOption}
          onChange={setDisplayOption}
          className="flex gap-1.5 mr-4"
        />
      </div>

      {/* Plain */}
      {displayOption === displayOptions[0] && (
        <div>
          {Array.from(
            {
              length: Math.min(firstFlow!.flow[firstFlowRepr].flow.length, secondFlow!.flow[secondFlowRepr].flow.length),
            },
            (_, i) => Flow(firstFlow!.flow[firstFlowRepr].flow[i].data, secondFlow!.flow[secondFlowRepr].flow[i].data)
          )}
        </div>
      )}

      {/* Hex */}
      {displayOption === displayOptions[1] && (
        <div>
          {Array.from(
            {
              length: Math.min(firstFlow!.flow[firstFlowRepr].flow.length, secondFlow!.flow[secondFlowRepr].flow.length),
            },
            (_, i) =>
              Flow(
                hexy(Buffer.from(firstFlow!.flow[firstFlowRepr].flow[i].b64, 'base64'), { format: "twos" }),
                hexy(Buffer.from(secondFlow!.flow[secondFlowRepr].flow[i].b64, 'base64'), { format: "twos" })
              )
          )}
        </div>
      )}
    </div>
  );
}
