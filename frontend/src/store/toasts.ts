import { createSlice, PayloadAction, nanoid } from "@reduxjs/toolkit";

export type ToastSeverity = "info" | "success" | "warning" | "danger";

export interface Toast {
  id: string;
  message: string;
  severity: ToastSeverity;
  ttl_ms: number;
  href?: string;        // optional link the toast navigates to on click
  href_label?: string;
}

interface State {
  items: Toast[];
}

const initialState: State = { items: [] };

interface PushPayload {
  message: string;
  severity?: ToastSeverity;
  ttl_ms?: number;
  href?: string;
  href_label?: string;
}

export const toastsSlice = createSlice({
  name: "toasts",
  initialState,
  reducers: {
    pushToast: {
      reducer: (state, action: PayloadAction<Toast>) => {
        state.items.push(action.payload);
        if (state.items.length > 30) state.items.shift();
      },
      prepare: (p: PushPayload) => ({
        payload: {
          id: nanoid(),
          message: p.message,
          severity: p.severity ?? "info",
          ttl_ms: p.ttl_ms ?? 6000,
          href: p.href,
          href_label: p.href_label,
        } as Toast,
      }),
    },
    dismissToast: (state, action: PayloadAction<string>) => {
      state.items = state.items.filter((t) => t.id !== action.payload);
    },
    clearToasts: (state) => {
      state.items = [];
    },
  },
});

export const { pushToast, dismissToast, clearToasts } = toastsSlice.actions;
export default toastsSlice.reducer;
