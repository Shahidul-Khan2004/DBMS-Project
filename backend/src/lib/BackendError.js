export default class BackendError extends Error {
  constructor(code, type, message, details) {
    super(message);
    this.name = "BackendError";
    this.code = code;
    this.type = type;
    this.details = details;
  }
}