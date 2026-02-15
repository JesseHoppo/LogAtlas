// App state + pub/sub.

const state = {
  fileTree: null,
  flatFiles: [],
  errors: [],
  rememberedPassword: null,
  currentPath: [],
  viewMode: 'list',
  rootZipName: '',
  fileContents: new Map(),
  loading: false,
  loadingText: '',
  sourceFile: null,
  filterText: '',
  filterBadges: [],
  filterGlobal: false,
  isMultiFileMode: false,
  virtualContainerName: 'Uploaded Files',
  manualTypeAssignments: new Map(),
};

const listeners = {};

function on(event, fn) {
  if (!listeners[event]) listeners[event] = [];
  listeners[event].push(fn);
}

function off(event, fn) {
  if (!listeners[event]) return;
  listeners[event] = listeners[event].filter(f => f !== fn);
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
  state.loading = !!text;
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
  state.isMultiFileMode = enabled;
  emit('multiFileMode', enabled);
}

function setManualType(filename, fileType) {
  state.manualTypeAssignments.set(filename, fileType);
}

function resetState() {
  state.fileTree = null;
  state.flatFiles = [];
  state.errors = [];
  state.rememberedPassword = null;
  state.currentPath = [];
  state.rootZipName = '';
  state.loading = false;
  state.loadingText = '';
  state.sourceFile = null;
  state.filterText = '';
  state.filterBadges = [];
  state.filterGlobal = false;
  state.isMultiFileMode = false;
  state.virtualContainerName = 'Uploaded Files';
  state.manualTypeAssignments.clear();
  state.fileContents.clear();

  emit('reset');
}

export { state, on, off, emit, resetState, setLoading, addError, setRememberedPassword, setMultiFileMode, setManualType };
