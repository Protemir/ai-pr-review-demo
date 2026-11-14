import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pluralize, truncate } from './format.ts';

test('pluralize', () => {
  assert.equal(pluralize(1, 'like', 'likes'), '1 like');
  assert.equal(pluralize(3, 'like', 'likes'), '3 likes');
});

test('truncate', () => {
  assert.equal(truncate('hello', 10), 'hello');
  assert.equal(truncate('hello world', 6), 'hello…');
});
