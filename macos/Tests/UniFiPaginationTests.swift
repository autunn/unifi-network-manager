import Foundation
import XCTest
@testable import UniFiPolicyManagerMac

final class UniFiPaginationTests: XCTestCase {
    func testPageCountDoesNotTerminateCollection() throws {
        let page = try OfficialResourcePresenter.parsePage(
            #"{"data":[{"id":"a"},{"id":"b"}],"count":2,"offset":0,"limit":2}"#,
            moduleID: "devices"
        )
        XCTAssertFalse(page.snapshot.hasReportedTotalCount)
        var pagination = UniFiPagination()
        XCTAssertTrue(try pagination.advance(
            rows: page.snapshot.items.count, totalCount: page.total, responseLimit: page.limit,
            responseOffset: page.offset, signature: page.signature
        ))
        XCTAssertEqual(pagination.offset, 2)
        XCTAssertFalse(try pagination.advance(rows: 1, responseLimit: 2, responseOffset: 2))
    }

    func testMissingPaginationMetadataStopsAtEmptyPage() throws {
        var pagination = UniFiPagination()
        XCTAssertTrue(try pagination.advance(rows: 1))
        XCTAssertFalse(try pagination.advance(rows: 0))
    }

    func testRejectsIncompleteOrRepeatedPages() throws {
        var knownTotal = UniFiPagination()
        XCTAssertTrue(try knownTotal.advance(rows: 2, totalCount: 4))
        XCTAssertThrowsError(try knownTotal.advance(rows: 0))

        var repeated = UniFiPagination()
        let signature = Data("repeat".utf8)
        XCTAssertTrue(try repeated.advance(rows: 2, signature: signature))
        XCTAssertThrowsError(try repeated.advance(rows: 2, signature: signature))
        var wrongOffset = UniFiPagination(offset: 2)
        XCTAssertThrowsError(try wrongOffset.advance(rows: 2, responseOffset: 0))
        XCTAssertThrowsError(try OfficialResourcePresenter.parsePage(#"{"data":null}"#, moduleID: "devices"))
    }
}
