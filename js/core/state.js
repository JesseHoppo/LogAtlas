// App state + pub/sub.

const state = {
  fileTree: null,
  flatFiles: [],
  errors: [],
  rememberedPassword: null,
  currentPath: [],
  viewMode: 'list',
  rootZipName: '',
  loadingText: '',
  sourceFile: null,
  filterText: '',
  isMultiFileMode: false,
  virtualContainerName: 'Uploaded Files',
};

const listeners = {};

function on(event, fn) {
  if (!listeners[event]) listeners[event] = [];
  listeners[event].push(fn);
}

function emit(event, data) {
  if (!listeners[event]) return;
  for (const fn of listeners[event]) {
    try {
      fn(data);
    } catch (err) {
      console.error(`[state] Error in "${event}" handler:`, err);
    }
  }
}

function setLoading(text) {
  state.loadingText = text || '';
  emit('loading');
}

const MAX_ERRORS = 200;

function addError(msg) {
  if (state.errors.length < MAX_ERRORS) {
    state.errors.push(msg);
  }
}

function setRememberedPassword(pw) {
  state.rememberedPassword = pw;
}

function setMultiFileMode(enabled) {
  state.isMultiFileMode = Boolean(enabled);
}

function resetState() {
  state.fileTree = null;
  state.flatFiles = [];
  state.errors = [];
  state.rememberedPassword = null;
  state.currentPath = [];
  state.rootZipName = '';
  state.loadingText = '';
  state.sourceFile = null;
  state.filterText = '';
  state.isMultiFileMode = false;
  state.virtualContainerName = 'Uploaded Files';

  emit('reset');
}

export { state, on, emit, resetState, setLoading, addError, setRememberedPassword, setMultiFileMode };
