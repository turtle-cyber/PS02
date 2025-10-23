import axios from "axios";

// Set the base URL for axios requests
axios.defaults.baseURL =
  import.meta.env.VITE_API_BASE || "http://192.168.142.128:3001/api";

export const http = {
  get: axios.get,
  post: axios.post,
  put: axios.put,
  delete: axios.delete,
  patch: axios.patch,
};
