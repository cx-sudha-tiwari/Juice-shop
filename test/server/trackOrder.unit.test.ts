/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { trackOrder } from '../../routes/trackOrder'
import * as db from '../../data/mongodb'
import * as utils from '../../lib/utils'
import * as challengeUtils from '../../lib/challengeUtils'
import { challenges } from '../../data/datacache'

void describe('trackOrder', () => {
  let req: any
  let res: any

  beforeEach(() => {
    req = { params: { id: 'ord-1234' } }
    res = { json: mock.fn(), status: mock.fn(() => res) }
    mock.restoreAll()
    // Disable the XSS challenge so the sanitizing branch runs
    mock.method(utils, 'isChallengeEnabled', () => false)
    mock.method(challengeUtils, 'solveIf', () => {})
    // Stub challenges so the import succeeds regardless of datacache state
    challenges.reflectedXssChallenge = challenges.reflectedXssChallenge ?? ({} as any)
    challenges.noSqlOrdersChallenge = challenges.noSqlOrdersChallenge ?? ({} as any)
  })

  void it('queries MongoDB using a safe document-object filter (no $where)', async () => {
    let capturedFilter: any
    mock.method(db.ordersCollection, 'find', (filter: any) => {
      capturedFilter = filter
      return Promise.resolve([{ orderId: 'ord-1234', status: 'shipped' }])
    })

    const handler = trackOrder()
    await new Promise<void>((resolve) => {
      res.json = () => { resolve() }
      handler(req, res, mock.fn())
    })

    // The query must NOT contain a $where clause
    assert.ok(!('$where' in capturedFilter), 'Query must not use $where (NoSQL injection sink)')
    // The query must match on the orderId field directly
    assert.ok('orderId' in capturedFilter, 'Query must use the orderId field directly')
    assert.equal(capturedFilter.orderId, 'ord-1234')
  })

  void it('returns the order data as JSON on success', async () => {
    const fakeOrder = [{ orderId: 'ord-1234', status: 'delivered' }]
    mock.method(db.ordersCollection, 'find', () => Promise.resolve(fakeOrder))

    const handler = trackOrder()
    const result = await new Promise<any>((resolve) => {
      res.json = (data: any) => { resolve(data) }
      handler(req, res, mock.fn())
    })

    assert.equal(result.status, 'success')
    assert.equal(result.data[0].orderId, 'ord-1234')
  })

  void it('returns a placeholder when no matching order is found', async () => {
    mock.method(db.ordersCollection, 'find', () => Promise.resolve([]))

    const handler = trackOrder()
    const result = await new Promise<any>((resolve) => {
      res.json = (data: any) => { resolve(data) }
      handler(req, res, mock.fn())
    })

    // When no order is found the route fills in a placeholder with the id
    assert.equal(result.data[0].orderId, 'ord-1234')
  })

  void it('responds with 400 when the database query rejects', async () => {
    mock.method(db.ordersCollection, 'find', () => Promise.reject(new Error('db error')))

    const handler = trackOrder()
    const statusCode = await new Promise<number>((resolve) => {
      res.status = (code: number) => {
        resolve(code)
        return res
      }
      res.json = () => {}
      handler(req, res, mock.fn())
    })

    assert.equal(statusCode, 400)
  })

  void it('strips special characters from id to prevent injection attempts', async () => {
    req.params.id = "ord-1234'; while(1){} //"
    let capturedFilter: any
    mock.method(db.ordersCollection, 'find', (filter: any) => {
      capturedFilter = filter
      return Promise.resolve([])
    })

    const handler = trackOrder()
    await new Promise<void>((resolve) => {
      res.json = () => { resolve() }
      handler(req, res, mock.fn())
    })

    // After stripping non-word/dash characters the dangerous payload must be gone
    assert.ok(!capturedFilter.orderId.includes("'"), 'Single quotes must be stripped')
    assert.ok(!capturedFilter.orderId.includes(';'), 'Semicolons must be stripped')
    assert.ok(!capturedFilter.orderId.includes('{'), 'Braces must be stripped')
    // Safe portion of the id must survive
    assert.ok(capturedFilter.orderId.includes('ord-1234'), 'Legitimate id portion must be kept')
  })

  void it('does not execute JavaScript via the orderId value', async () => {
    // If the old $where sink were still present, injecting a JS expression
    // such as "' || true || '" would return all documents. With the safe
    // document-object query the value is treated as a literal string and
    // cannot match anything (after sanitization it becomes an empty string).
    req.params.id = "' || '1'=='1"
    let capturedFilter: any
    mock.method(db.ordersCollection, 'find', (filter: any) => {
      capturedFilter = filter
      return Promise.resolve([])
    })

    const handler = trackOrder()
    await new Promise<void>((resolve) => {
      res.json = () => { resolve() }
      handler(req, res, mock.fn())
    })

    assert.ok(!('$where' in capturedFilter), 'Injection payload must not be placed inside a $where clause')
  })
})
