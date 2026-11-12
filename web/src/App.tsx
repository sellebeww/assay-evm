import { useCallback, useState, type ChangeEvent, type DragEvent } from "react";
import { ReportView } from "./components/Report";
import { parseReport, type ParseResult } from "./model";

const SAMPLES = ["rejected", "inconclusive", "verified"] as const;
const MAX_BYTES = 5 * 1024 * 1024;

export function App() {
  const [result, setResult] = useState<ParseResult | null>(null);
  const [name, setName] = useState<string | null>(null);
  const [synthetic, setSynthetic] = useState(false);

  const load = useCallback((text: string, label: string, isSample: boolean) => {
    setResult(parseReport(text));
    setName(label);
    setSynthetic(isSample);
  }, []);

  const readFile = useCallback(
    async (file: File) => {
      if (file.size > MAX_BYTES) {
        setResult({ ok: false, errors: ["The file is larger than 5 MiB."] });
        setName(file.name);
        return;
      }
      load(await file.text(), file.name, false);
    },
    [load],
  );

  const onPick = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file !== undefined) void readFile(file);
  };
  const onDrop = (event: DragEvent<HTMLLabelElement>) => {
    event.preventDefault();
    const file = event.dataTransfer.files[0];
    if (file !== undefined) void readFile(file);
  };
  const loadSample = async (sample: string) => {
    const response = await fetch(`./samples/${sample}.json`);
    load(await response.text(), `${sample}.json`, true);
  };

  return (
    <main>
      <h1>Assay report viewer</h1>
      <p className="lead">
        Open the JSON of <code>assay verify --json</code>. The file is read in your browser and is
        never uploaded: there is no backend.
      </p>

      <label
        className="drop"
        onDragOver={(event) => event.preventDefault()}
        onDrop={onDrop}
      >
        <span>Drop a report here or choose a file</span>
        <input type="file" accept="application/json,.json" onChange={onPick} />
      </label>

      <p className="samples">
        Or try a synthetic example:{" "}
        {SAMPLES.map((sample) => (
          <button key={sample} type="button" onClick={() => void loadSample(sample)}>
            {sample}
          </button>
        ))}
      </p>

      {result !== null && name !== null && (
        <section aria-live="polite">
          <h2 className="file">
            <code>{name}</code>
          </h2>
          {synthetic && (
            <p className="notice">
              Synthetic example built to show the layout. It is not the result of a real run.
            </p>
          )}
          {result.ok ? (
            <ReportView report={result.report} />
          ) : (
            <div className="error" role="alert">
              <p>This file cannot be shown:</p>
              <ul>
                {result.errors.map((message) => (
                  <li key={message}>{message}</li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}

      <footer>
        A verdict means that nothing was found within the recorded bounds. It is not a proof of
        correctness. Text in a report can come from a project or a patch, so the viewer shows it as
        text only.
      </footer>
    </main>
  );
}
