/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { trackOrder } from '../../routes/trackOrder'
import * as db from '../../data/mongodb'
import * as challengeUtils from '../../lib/challengeUtils'
import { challenges } from '../../data/datacache'

void describe('trackOrder', () => {
  let req: any
  let res: any

  beforeEach(() => {
    req = { params: { id: 'TEST-ORDER-123' } }
    res = { json: mock.fn(), status: mock.fn(() => res) }
    mock.restoreAll()
    // Disable XSS challenge so the sanitized branch is used by default
    mock.method(challenges, 'reflectedXssChallenge', { name: 'reflectedXssChallenge' }, { getter: true })
  })

  void it('should call ordersCollection.find with a plain document filter (no $where)', async () => {
    let capturedQuery: any
    mock.method(db.ordersCollection, 'find', (query: any) => {
      capturedQuery = query
      return Promise.resolve([])
    })
    mock.method(challengeUtils, 'solveIf', () => {})

    const p = new Promise<void>((resolve) => {
      res.json = () => { resolve() }
    })

    trackOrder()(req, res)
    await p

    // The query must NOT use a $where clause — that is the injection sink
    assert.strictEqual(capturedQuery.$where, undefined, 'Query must not contain a $where clause')
    // The query must use a plain equality filter on orderId
    assert.ok('orderId' in capturedQuery, 'Query must filter by orderId field directly')
    assert.strictEqual(capturedQuery.orderId, 'TEST-ORDER-123')
  })

  void it('should NOT interpolate the order id into a JavaScript string for $where', async () => {
    // Any $where string containing the raw id value indicates the injection sink is still present
    let capturedQuery: any
    const injectionAttempt = "' ; while(1){} ; '"
    req.params.id = injectionAttempt

    mock.method(db.ordersCollection, 'find', (query: any) => {
      capturedQuery = query
      return Promise.resolve([])
    })
    mock.method(challengeUtils, 'solveIf', () => {})

    const p = new Promise<void>((resolve) => {
      res.json = () => { resolve() }
    })

    trackOrder()(req, res)
    await p

    assert.strictEqual(capturedQuery.$where, undefined, '$where clause must not be present regardless of input')
  })

  void it('should return a placeholder result when no order is found', async () => {
    mock.method(db.ordersCollection, 'find', () => Promise.resolve([]))
    mock.method(challengeUtils, 'solveIf', () => {})

    let responseData: any
    const p = new Promise<void>((resolve) => {
      res.json = (data: any) => { responseData = data; resolve() }
    })

    trackOrder()(req, res)
    await p

    // When no order is found the route fills in a placeholder with the queried orderId
    assert.ok(responseData.data, 'Response should contain a data field')
    assert.ok(Array.isArray(responseData.data), 'data should be an array')
    assert.ok(responseData.data[0] !== undefined, 'A placeholder entry should be present')
  })

  void it('should respond with 400 on database error', async () => {
    mock.method(db.ordersCollection, 'find', () => Promise.reject(new Error('db error')))
    mock.method(challengeUtils, 'solveIf', () => {})

    const p = new Promise<void>((resolve) => {
      res.json = () => { resolve() }
    })

    trackOrder()(req, res)
    await p

    assert.ok(res.status.mock.calls.length > 0, 'status() should have been called')
    assert.strictEqual(res.status.mock.calls[0].arguments[0], 400)
  })

  void it('should return matching order data when order exists', async () => {
    const fakeOrder = [{ orderId: 'TEST-ORDER-123', totalPrice: 9.99 }]
    mock.method(db.ordersCollection, 'find', () => Promise.resolve(fakeOrder))
    mock.method(challengeUtils, 'solveIf', () => {})

    let responseData: any
    const p = new Promise<void>((resolve) => {
      res.json = (data: any) => { responseData = data; resolve() }
    })

    trackOrder()(req, res)
    await p

    assert.strictEqual(responseData.data[0].orderId, 'TEST-ORDER-123')
    assert.strictEqual(responseData.data[0].totalPrice, 9.99)
  })

  void it('should pass the id value directly as a field value, not as executable JS', async () => {
    // Regression guard: confirm the find call uses { orderId: <value> } regardless of what the value is
    const payloads = [
      "1' OR '1'='1",
      "'; return true; var x='",
      '1; db.dropDatabase()',
      '<script>alert(1)</script>'
    ]

    for (const payload of payloads) {
      req.params.id = payload
      let capturedQuery: any
      mock.method(db.ordersCollection, 'find', (query: any) => {
        capturedQuery = query
        return Promise.resolve([])
      })
      mock.method(challengeUtils, 'solveIf', () => {})

      const p = new Promise<void>((resolve) => {
        res.json = () => { resolve() }
      })

      trackOrder()(req, res)
      await p

      assert.strictEqual(capturedQuery.$where, undefined,
        `$where must not be present for payload: ${payload}`)
      assert.ok('orderId' in capturedQuery,
        `orderId field must be present for payload: ${payload}`)
      mock.restoreAll()
    }
  })
})
