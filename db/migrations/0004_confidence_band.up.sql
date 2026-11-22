-- confidence band column for the incident list. the band comes from the
-- analysis document (the engine's diagnosis.BandFor), copied by
-- metadata.go. it is not recomputed from `confidence`: that column is REAL,
-- and a score of exactly 0.90 reads back as 0.8999999761581421, which would
-- fall into the band below.
begin;

alter table incidents add column if not exists confidence_band TEXT;

-- backfill rows written before this migration. rounding to 4 places undoes
-- the REAL error; the boundaries are diagnosis.BandFor's (0.90/0.75/0.55).
-- new and re-analyzed rows take the band from the document instead.
update incidents set confidence_band = case
    when round(confidence::numeric, 4) >= 0.90 then 'VERY_HIGH'
    when round(confidence::numeric, 4) >= 0.75 then 'HIGH'
    when round(confidence::numeric, 4) >= 0.55 then 'MODERATE'
    else 'NONE'
  end
where confidence is not null and confidence_band is null;

commit;
