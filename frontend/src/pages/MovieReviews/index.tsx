import { AxiosRequestConfig } from 'axios';
import ButtonIcon from 'components/ButtonIcon';
import { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { useParams } from 'react-router-dom';
import StarImg from 'assets/images/star.png';
import { Reviews } from 'types/reviews';
import { BASE_URL, requestBackend } from 'util/requests';
import MovieReviewsLoader from './MovieReviewsLoader';
import { hasAnyRoles } from 'util/auth';

import './styles.css';
import ReviewMovieCard from 'components/ReviewMovieCard';
import { toast } from 'react-toastify';

type UrlParams = {
  movieId: string;
};

type FormData = {
  text: string;
  movieId: string;
};

const MovieReviews = () => {
  const { movieId } = useParams<UrlParams>();
  const [addReview, setAddReview] = useState(false);
  const [reviewList, setReviewList] = useState<Reviews[]>();
  const [isLoading, setIsLoading] = useState(false);
  const [haveList, setHaveList] = useState(0);

  const {
    register,
    handleSubmit,
    setValue,
    formState: { errors },
  } = useForm<FormData>();

  useEffect(() => {
    const params: AxiosRequestConfig = {
      method: 'GET',
      url: `${BASE_URL}/movies/${movieId}/reviews`,
      withCredentials: true,
    };
    setIsLoading(true);
    requestBackend(params)
      .then((response) => {
        setReviewList(response.data);
      })
      .finally(() => {
        setIsLoading(false);
        setAddReview(false);
      });
  }, [addReview, movieId]);

  useEffect(() => {
    setHaveList(reviewList?.length ? reviewList.length : 0);
  }, [reviewList]);

  const onSubmit = (currentData: FormData) => {
    const config: AxiosRequestConfig = {
      method: 'POST',
      url: '/reviews',
      withCredentials: true,
      data: currentData,
    };
    requestBackend(config)
      .then((response) => {
        if (response.status === 201) {
          toast.success('Avaliação gravada com sucesso!');
          setAddReview(true);
          setValue('text', '');
        }
      })
      .catch(() => {
        toast.error('Não foi possível registrar a avaliação...');
      });
  };

  return (
    <div className="reviews-details-container">
      <div className="review-all-container">
        <div className="title-container">
          <ReviewMovieCard movieId={movieId} />
        </div>

        {/* --------------- INICIO FORMULARIO ------------- */}
        {hasAnyRoles(['ROLE_MEMBER']) && (
          <div className="aval-card">
            <form onSubmit={handleSubmit(onSubmit)}>
              <input
                type="hidden"
                {...register('movieId')}
                className={'form-control base-input'}
                name="movieId"
                value={movieId}
              />
              <div className="input-box review-input-box">
                <input
                  {...register('text', {
                    required: 'Campo obrigatório',
                  })}
                  type="text"
                  className={`form-control base-input ${
                    errors.text ? 'Favor preencher a revisão' : ''
                  }`}
                  placeholder="Deixe sua avaliação aqui"
                  name="text"
                />
                <div className="invalid-feedback d-block">
                  {errors.text?.message}
                </div>
              </div>
              <div className="aval-submit">
                <ButtonIcon text="Salvar Avaliação" />
              </div>
            </form>
          </div>
        )}
        {/* ----------------- FIM FORMULARIO -------------- */}

        <div className="base-card row-reviews">
          {isLoading ? (
            <MovieReviewsLoader />
          ) : haveList > 0 ? (
            reviewList?.map((x) => (
              <div className="row-detail" key={x.id}>
                <div className="row-detail-title">
                  <img src={StarImg} alt="Estrela Amarela" />
                  <h1>{x.user.name}</h1>
                </div>
                <div className="row-detail-obs">
                  <p>{x.text}</p>
                </div>
              </div>
            ))
          ) : (
            <div className="row-detail-empty">
              <p>Sem Avaliações</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default MovieReviews;
