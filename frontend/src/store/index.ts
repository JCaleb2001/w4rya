import { configureStore } from "@reduxjs/toolkit";
import { setupListeners } from "@reduxjs/toolkit/query";
import { useDispatch, useSelector } from "react-redux";
import type { TypedUseSelectorHook } from "react-redux";

import { w4ryaApi } from "../api";

import filterReducer from "./filter";
import toastsReducer from "./toasts";

export const store = configureStore({
  reducer: {
    [w4ryaApi.reducerPath]: w4ryaApi.reducer,
    filter: filterReducer,
    toasts: toastsReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat(w4ryaApi.middleware),
});

setupListeners(store.dispatch);

// Use throughout your app instead of plain `useDispatch` and `useSelector`
export const useAppDispatch: () => typeof store.dispatch = useDispatch;
export const useAppSelector: TypedUseSelectorHook<
  ReturnType<typeof store.getState>
> = useSelector;
