import { EVIDENCE_TEXT, VERDICT_TEXT, type OracleRow, type Reason, type Report } from "../model";

function ReasonItem({ reason }: { reason: Reason }) {
  const where =
    reason.path === null ? null : `${reason.path}${reason.line === null ? "" : `:${reason.line}`}`;
  return (
    <li>
      <code>{reason.code}</code> {reason.detail}
      {where !== null && (
        <>
          {" "}
          <span className="where">{where}</span>
        </>
      )}
    </li>
  );
}

function OracleCard({ row }: { row: OracleRow }) {
  const state = row.verdict ?? row.status;
  return (
    <section className={`oracle oracle-${state.toLowerCase()}`} aria-label={`${row.oracle} oracle`}>
      <header>
        <h3>{row.oracle}</h3>
        <span className="badge" data-state={state.toLowerCase()}>
          {row.verdict ?? `not run (${row.status})`}
        </span>
      </header>
      {row.summary !== "" && <p className="summary">{row.summary}</p>}
      {row.reasons.length > 0 && (
        <ul className="reasons">
          {row.reasons.map((reason, index) => (
            <ReasonItem key={index} reason={reason} />
          ))}
        </ul>
      )}
      {row.warnings.length > 0 && (
        <>
          <h4>Warnings</h4>
          <ul className="reasons">
            {row.warnings.map((reason, index) => (
              <ReasonItem key={index} reason={reason} />
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

function Value({ value }: { value: unknown }) {
  if (value === null || value === undefined) return <span className="muted">none</span>;
  if (typeof value === "object") return <pre>{JSON.stringify(value, null, 2)}</pre>;
  return <>{String(value)}</>;
}

export function ReportView({ report }: { report: Report }) {
  return (
    <article>
      <div className={`verdict verdict-${report.finalVerdict.toLowerCase()}`} role="status">
        <h2>{report.finalVerdict}</h2>
        <p>{VERDICT_TEXT[report.finalVerdict]}</p>
        {report.evidenceLevel !== null && (
          <p>
            Evidence level <strong>{report.evidenceLevel}</strong>:{" "}
            {EVIDENCE_TEXT[report.evidenceLevel] ?? "unknown level"}
          </p>
        )}
        {report.integrityViolation && (
          <p className="integrity">Integrity violation: the patch touched something it must not.</p>
        )}
        {report.reasons.length > 0 && (
          <p>
            Reasons: {report.reasons.map((code) => (
              <code key={code}>{code}</code>
            ))}
          </p>
        )}
      </div>

      <h2>Oracles</h2>
      <div className="oracles">
        {report.oracles.map((row) => (
          <OracleCard key={row.oracle} row={row} />
        ))}
      </div>

      <h2>Bounds</h2>
      <p>
        A verdict is valid within these bounds only: a bounded search cannot show that no variant
        exists.
      </p>
      {report.boundsStatement !== "" && <p className="statement">{report.boundsStatement}</p>}
      {report.annotations.length > 0 && (
        <ul>
          {report.annotations.map((note, index) => (
            <li key={index}>{note}</li>
          ))}
        </ul>
      )}
      <table>
        <tbody>
          {Object.entries(report.bounds).map(([key, value]) => (
            <tr key={key}>
              <th scope="row">{key}</th>
              <td>
                <Value value={value} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Inputs</h2>
      <table>
        <tbody>
          {Object.entries(report.inputs).map(([key, value]) => (
            <tr key={key}>
              <th scope="row">{key}</th>
              <td>{value === null ? <span className="muted">none</span> : <code>{value}</code>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {report.totalSeconds !== null && (
        <p className="muted">Oracles took {report.totalSeconds} s in total.</p>
      )}
    </article>
  );
}
