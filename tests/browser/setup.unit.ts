// Unit test setup file
// In jsdom environment, localStorage is available on window
// Tests create their own config instances as needed

// Verify jsdom localStorage is working
if (typeof window !== 'undefined' && window.localStorage) {
  // jsdom provides localStorage - no additional setup needed
  console.log('jsdom localStorage available');
} else {
  console.warn('jsdom localStorage not available - tests may fail');
}
